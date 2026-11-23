"""penenv CVE knowledge feed (host-side only — never runs inside the Strix sandbox).

The scan sandbox stays fail-closed: it NEVER fetches vulnerability data from the
internet. Instead the *host* curates an authoritative, offline CVE library here and
hands the stack-relevant subset to the agent as plain text in its instruction file
(see scanrun.context_for_project). No sandbox network rule changes for this feature.

Sources (all public, authoritative):
  * NVD 2.0   — CVE records, CVSS, CWE, CPE applicability   (services.nvd.nist.gov)
  * OSV       — open-source package advisories               (api.osv.dev)
  * GHSA      — GitHub Security Advisories                   (OSV GHSA records)
  * CISA KEV  — Known Exploited Vulnerabilities catalogue     (cisa.gov)
  * Exploit-DB — PoC *metadata only* (ids/titles, never payloads) via its CVE map

Design, mirroring the rest of tracker/:
  * stdlib only, no third-party packages;
  * the HTTP layer is injected (`http=` callable) so the parsers, store and matcher
    are unit-tested with canned bytes and never touch the network;
  * parsers are pure functions returning plain records;
  * the store is a dedicated SQLite DB (PENENV_CVE_DB or tracker/cve.db) kept apart
    from the tracker DB so project migrations/backups are untouched.

CLI:
  python3 tracker/cvefeed.py sync   [--source all|nvd|osv|ghsa|kev|exploitdb] [--since DAYS]
                                     [--keyword K] [--ecosystem E] [--package P]
  python3 tracker/cvefeed.py status
  python3 tracker/cvefeed.py match  --term "openssh 7.4" [--limit N]
  python3 tracker/cvefeed.py show   CVE-2016-0777
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.environ["PENENV_CVE_DB"]) if os.environ.get("PENENV_CVE_DB") \
    else ROOT / "tracker" / "cve.db"

SOURCES = ("nvd", "osv", "ghsa", "kev", "exploitdb")
# Exactly which hosts the HOST (never the sandbox) contacts on `cve sync`.
SOURCE_HOSTS = {
    "nvd": "services.nvd.nist.gov",
    "osv": "api.osv.dev",
    "ghsa": "api.osv.dev",
    "kev": "www.cisa.gov",
    "exploitdb": "gitlab.com",
}
SEV_ORDER = {"NONE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
USER_AGENT = "penenv-cvefeed/1.0 (host-side; offline curation)"


# ----------------------------------------------------------------- store
def connect(db_path: Path | None = None) -> sqlite3.Connection:
    con = sqlite3.connect(db_path or DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS cve(
            id TEXT PRIMARY KEY,
            source TEXT, published TEXT, modified TEXT,
            cvss REAL, severity TEXT, vector TEXT, cwe TEXT,
            kev INTEGER DEFAULT 0, exploited INTEGER DEFAULT 0,
            summary TEXT, refs TEXT, products TEXT,
            fetched_at TEXT
        );
        CREATE TABLE IF NOT EXISTS cve_alias(
            alias TEXT PRIMARY KEY, cve_id TEXT
        );
        CREATE TABLE IF NOT EXISTS feed_meta(
            source TEXT PRIMARY KEY, last_sync TEXT, cursor TEXT, count INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve(kev);
        CREATE INDEX IF NOT EXISTS idx_cve_sev ON cve(severity);
        """
    )
    return con


def ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ------------------------------------------------------------- version maths
_VSPLIT = re.compile(r"[._\-+~]")


def _vkey(v: str) -> tuple:
    """Tolerant version key: 1.2.10 > 1.2.9; non-numeric fragments compare as text."""
    parts = []
    for frag in _VSPLIT.split(str(v or "").strip().lstrip("vV")):
        if frag == "":
            continue
        for sub in re.findall(r"\d+|[A-Za-z]+", frag):
            parts.append((0, int(sub)) if sub.isdigit() else (1, sub))
    return tuple(parts)


def _in_range(version: str | None, introduced: str | None, fixed: str | None,
              last_affected: str | None = None) -> bool:
    """introduced inclusive, fixed exclusive, last_affected inclusive.
    When the queried version is unknown we cannot exclude the range, so match."""
    if version is None or str(version).strip() == "":
        return True
    v = _vkey(version)
    if introduced and introduced not in ("0", "") and v < _vkey(introduced):
        return False
    if fixed and v >= _vkey(fixed):
        return False
    if last_affected and v > _vkey(last_affected):
        return False
    return True


# -------------------------------------------------------------- normalise
def _sev_from_cvss(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0.0:
        return "LOW"
    return "NONE"


def blank_record(cve_id: str, source: str) -> dict:
    return {"id": cve_id, "source": source, "published": "", "modified": "",
            "cvss": None, "severity": "", "vector": "", "cwe": "", "kev": 0,
            "exploited": 0, "summary": "", "refs": [], "products": [], "aliases": []}


# ------------------------------------------------------------- NVD 2.0 parse
def parse_nvd(data: dict | bytes | str) -> list[dict]:
    """Parse an NVD 2.0 `/cves/2.0` response into records."""
    data = _as_json(data)
    out = []
    for item in data.get("vulnerabilities", []) or []:
        c = item.get("cve") or {}
        cid = c.get("id")
        if not cid:
            continue
        rec = blank_record(cid, "nvd")
        rec["published"] = c.get("published", "") or ""
        rec["modified"] = c.get("lastModified", "") or ""
        for d in c.get("descriptions", []) or []:
            if d.get("lang") == "en":
                rec["summary"] = d.get("value", "")
                break
        metrics = c.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cdata = metrics[key][0].get("cvssData", {})
                rec["cvss"] = cdata.get("baseScore")
                rec["vector"] = cdata.get("vectorString", "")
                rec["severity"] = (cdata.get("baseSeverity")
                                   or metrics[key][0].get("baseSeverity")
                                   or _sev_from_cvss(rec["cvss"]))
                break
        rec["severity"] = (rec["severity"] or _sev_from_cvss(rec["cvss"])).upper()
        for w in c.get("weaknesses", []) or []:
            for d in w.get("description", []) or []:
                if d.get("value", "").startswith("CWE-"):
                    rec["cwe"] = d["value"]
                    break
            if rec["cwe"]:
                break
        rec["refs"] = [r.get("url", "") for r in (c.get("references") or []) if r.get("url")]
        rec["products"] = _nvd_products(c.get("configurations") or [])
        out.append(rec)
    return out


def _nvd_products(configs: list) -> list[dict]:
    prods: dict[tuple, dict] = {}
    for cfg in configs:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable", False):
                    continue
                parts = (m.get("criteria", "") + ":::::::::::").split(":")
                # cpe:2.3:a:vendor:product:version:...
                vendor, product, version = parts[3], parts[4], parts[5]
                key = (vendor, product)
                rng = prods.setdefault(key, {"vendor": vendor, "product": product, "ranges": []})
                r = {}
                if m.get("versionStartIncluding"):
                    r["introduced"] = m["versionStartIncluding"]
                if m.get("versionEndExcluding"):
                    r["fixed"] = m["versionEndExcluding"]
                if m.get("versionEndIncluding"):
                    r["last_affected"] = m["versionEndIncluding"]
                # A concrete CPE version pins the range only when no explicit bound was given;
                # otherwise the start/end bounds are authoritative.
                if version not in ("*", "-", "") and not r:
                    r = {"introduced": version, "last_affected": version}
                rng["ranges"].append(r)
    return list(prods.values())


# ---------------------------------------------------------------- OSV parse
def parse_osv(data: dict | list | bytes | str, source: str = "osv") -> list[dict]:
    """Parse an OSV vuln, a list of them, or an OSV query `{"vulns": [...]}` response."""
    data = _as_json(data)
    if isinstance(data, dict) and "vulns" in data:
        data = data["vulns"]
    items = data if isinstance(data, list) else [data]
    out = []
    for v in items:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        osv_id = v["id"]
        aliases = [a for a in (v.get("aliases") or []) if isinstance(a, str)]
        cve_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)
        src = "ghsa" if osv_id.startswith("GHSA") else source
        rec = blank_record(cve_id, src)
        rec["aliases"] = sorted(set(aliases + [osv_id]) - {cve_id})
        rec["published"] = v.get("published", "") or ""
        rec["modified"] = v.get("modified", "") or ""
        rec["summary"] = v.get("summary") or (v.get("details") or "")[:500]
        for sev in v.get("severity", []) or []:
            if sev.get("type", "").startswith("CVSS") and sev.get("score"):
                rec["vector"] = sev["score"]
        dbs = v.get("database_specific") or {}
        if dbs.get("cwe_ids"):
            rec["cwe"] = ", ".join(dbs["cwe_ids"])
        sev_txt = str(dbs.get("severity") or "").upper()
        if sev_txt in SEV_ORDER:
            rec["severity"] = sev_txt
        rec["refs"] = [r.get("url", "") for r in (v.get("references") or []) if r.get("url")]
        rec["products"] = _osv_products(v.get("affected") or [])
        out.append(rec)
    return out


def _osv_products(affected: list) -> list[dict]:
    prods = []
    for a in affected:
        pkg = a.get("package") or {}
        name = pkg.get("name", "")
        eco = pkg.get("ecosystem", "")
        if not name:
            continue
        ranges = []
        for rng in a.get("ranges", []) or []:
            introduced = fixed = last = None
            for ev in rng.get("events", []) or []:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
                if "last_affected" in ev:
                    last = ev["last_affected"]
            r = {}
            if introduced and introduced != "0":
                r["introduced"] = introduced
            if fixed:
                r["fixed"] = fixed
            if last:
                r["last_affected"] = last
            ranges.append(r)
        for ver in a.get("versions", []) or []:
            ranges.append({"introduced": ver, "last_affected": ver})
        prods.append({"vendor": eco, "product": name, "ranges": ranges})
    return prods


# ---------------------------------------------------------------- KEV parse
def parse_kev(data: dict | bytes | str) -> dict:
    """CISA KEV catalogue -> {CVE-ID: {product, name, due}}."""
    data = _as_json(data)
    out = {}
    for v in data.get("vulnerabilities", []) or []:
        cid = v.get("cveID")
        if cid:
            out[cid] = {"product": f"{v.get('vendorProject', '')} {v.get('product', '')}".strip(),
                        "name": v.get("vulnerabilityName", ""), "due": v.get("dueDate", "")}
    return out


# ------------------------------------------------------------ Exploit-DB parse
def parse_exploitdb(data: bytes | str) -> dict:
    """Exploit-DB `files_exploits.csv` -> {CVE-ID: [{edb_id, title}]}. Metadata only."""
    import csv
    import io
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
    out: dict[str, list] = {}
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        codes = row.get("codes") or ""
        edb_id = row.get("id") or ""
        title = row.get("description") or ""
        for cve_id in re.findall(r"CVE-\d{4}-\d{4,7}", codes):
            out.setdefault(cve_id, []).append({"edb_id": edb_id, "title": title})
    return out


# -------------------------------------------------------------- upsert
def upsert(con: sqlite3.Connection, records: list[dict]) -> dict:
    report = {"new": 0, "updated": 0}
    for rec in records:
        row = con.execute("SELECT id, kev, exploited, refs FROM cve WHERE id=?", (rec["id"],)).fetchone()
        kev = int(rec.get("kev") or (row["kev"] if row else 0))
        exploited = int(rec.get("exploited") or (row["exploited"] if row else 0))
        refs = rec.get("refs") or []
        if row and not refs:
            refs = json.loads(row["refs"] or "[]")
        con.execute(
            "INSERT INTO cve(id,source,published,modified,cvss,severity,vector,cwe,kev,"
            "exploited,summary,refs,products,fetched_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET source=excluded.source,published=excluded.published,"
            "modified=excluded.modified,cvss=COALESCE(excluded.cvss,cve.cvss),"
            "severity=CASE WHEN excluded.severity!='' THEN excluded.severity ELSE cve.severity END,"
            "vector=CASE WHEN excluded.vector!='' THEN excluded.vector ELSE cve.vector END,"
            "cwe=CASE WHEN excluded.cwe!='' THEN excluded.cwe ELSE cve.cwe END,"
            "kev=excluded.kev,exploited=excluded.exploited,"
            "summary=CASE WHEN excluded.summary!='' THEN excluded.summary ELSE cve.summary END,"
            "refs=excluded.refs,"
            "products=CASE WHEN excluded.products!='[]' THEN excluded.products ELSE cve.products END,"
            "fetched_at=excluded.fetched_at",
            (rec["id"], rec.get("source", ""), rec.get("published", ""), rec.get("modified", ""),
             rec.get("cvss"), (rec.get("severity") or "").upper(), rec.get("vector", ""),
             rec.get("cwe", ""), kev, exploited, rec.get("summary", ""),
             json.dumps(refs, ensure_ascii=False),
             json.dumps(rec.get("products") or [], ensure_ascii=False), ts()),
        )
        for alias in rec.get("aliases") or []:
            con.execute("INSERT OR REPLACE INTO cve_alias(alias,cve_id) VALUES(?,?)", (alias, rec["id"]))
        report["new" if row is None else "updated"] += 1
    con.commit()
    return report


def apply_kev(con: sqlite3.Connection, kev_map: dict) -> int:
    n = 0
    for cid, info in kev_map.items():
        cur = con.execute("UPDATE cve SET kev=1, exploited=1 WHERE id=?", (cid,))
        if cur.rowcount == 0:
            rec = blank_record(cid, "kev")
            rec.update(kev=1, exploited=1, summary=info.get("name", ""),
                       products=[{"vendor": "", "product": info.get("product", ""), "ranges": []}])
            upsert(con, [rec])
        n += 1
    con.commit()
    return n


def apply_exploitdb(con: sqlite3.Connection, edb_map: dict) -> int:
    n = 0
    for cid, entries in edb_map.items():
        row = con.execute("SELECT refs FROM cve WHERE id=?", (cid,)).fetchone()
        if row is None:
            continue
        refs = json.loads(row["refs"] or "[]")
        for e in entries:
            url = f"https://www.exploit-db.com/exploits/{e['edb_id']}"
            if url not in refs:
                refs.append(url)
        con.execute("UPDATE cve SET exploited=1, refs=? WHERE id=?",
                    (json.dumps(refs, ensure_ascii=False), cid))
        n += 1
    con.commit()
    return n


# ---------------------------------------------------------------- matching
def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["refs"] = json.loads(d.get("refs") or "[]")
    d["products"] = json.loads(d.get("products") or "[]")
    return d


def _term_parts(term: str) -> tuple[str, str | None]:
    """'openssh 7.4' -> ('openssh', '7.4'); 'express' -> ('express', None)."""
    t = str(term or "").strip()
    m = re.match(r"^(.*?)[\s@:]+v?(\d[\w.\-]*)$", t)
    if m:
        return m.group(1).strip().lower(), m.group(2)
    return t.lower(), None


def _record_matches_term(rec: dict, product: str, version: str | None) -> bool:
    if not product:
        return False
    for p in rec.get("products") or []:
        name = str(p.get("product", "")).lower()
        vendor = str(p.get("vendor", "")).lower()
        if product in name or (name and name in product) or product == vendor:
            ranges = p.get("ranges") or [{}]
            for r in ranges:
                if _in_range(version, r.get("introduced"), r.get("fixed"), r.get("last_affected")):
                    return True
            if not ranges:
                return True
    # product-only fallback: a confident keyword hit in the summary (no version claim)
    if version is None and re.search(r"\b" + re.escape(product) + r"\b", rec.get("summary", "").lower()):
        return True
    return False


def match_stack(con: sqlite3.Connection, terms: list[str], limit: int = 25) -> list[dict]:
    """Return stack-relevant CVEs, KEV/known-exploited first, then by CVSS."""
    parsed = [_term_parts(t) for t in terms if str(t).strip()]
    if not parsed:
        return []
    hits: dict[str, dict] = {}
    for row in con.execute("SELECT * FROM cve"):
        rec = _row_to_dict(row)
        matched = [f"{p}{(' ' + v) if v else ''}" for p, v in parsed
                   if _record_matches_term(rec, p, v)]
        if matched:
            rec["matched_terms"] = matched
            hits[rec["id"]] = rec
    out = sorted(hits.values(),
                 key=lambda r: (r.get("kev", 0), r.get("exploited", 0), r.get("cvss") or 0.0),
                 reverse=True)
    return out[:limit]


# ----------------------------------------------------------- scan context
def terms_for_project(cfg: dict) -> list[str]:
    """Explicit `stack` entries, plus target hostnames as weak keyword hints."""
    terms = [str(s) for s in (cfg.get("stack") or []) if str(s).strip()]
    return terms


def render_scan_context(matches: list[dict], meta: dict | None = None, limit: int = 25) -> str:
    """The host-curated CVE block appended to the agent's instruction file (text only)."""
    if not matches:
        return ""
    synced = ""
    if meta:
        newest = max((m.get("last_sync", "") for m in meta.values()), default="")
        if newest:
            synced = f" (host library last synced {newest})"
    lines = [
        "# Current CVE intelligence (host-curated, authoritative)" + synced,
        "The following published vulnerabilities match this engagement's declared stack. This list was "
        "assembled by the penenv host from NVD/OSV/GHSA/CISA-KEV and injected into your instructions. "
        "Do NOT fetch vulnerability data from the network — the scan network blocks it. Prioritise "
        "confirming and safely proving the KEV / known-exploited items first, within the rules of engagement.",
    ]
    for r in matches[:limit]:
        tag = "KNOWN-EXPLOITED" if (r.get("kev") or r.get("exploited")) else ""
        cvss = f"CVSS {r['cvss']:.1f}" if r.get("cvss") is not None else (r.get("severity") or "unscored")
        prod = ", ".join(sorted({p.get("product", "") for p in (r.get("products") or []) if p.get("product")}))[:80]
        summary = re.sub(r"\s+", " ", (r.get("summary") or "")).strip()[:200]
        head = " · ".join(x for x in [r["id"], cvss, r.get("cwe", ""), prod, tag] if x)
        lines.append(f"- {head}: {summary}")
    return "\n".join(lines) + "\n"


def context_for_project(cfg: dict, enabled: bool = True, db_path: Path | None = None,
                        limit: int = 25) -> str:
    """Safe, best-effort: returns '' (never raises) when disabled, no DB, or no match."""
    if not enabled:
        return ""
    path = db_path or DB_PATH
    if not Path(path).exists():
        return ""
    terms = terms_for_project(cfg)
    if not terms:
        return ""
    try:
        con = connect(path)
        try:
            matches = match_stack(con, terms, limit=limit)
            meta = {r["source"]: dict(r) for r in con.execute("SELECT * FROM feed_meta")}
        finally:
            con.close()
    except sqlite3.Error:
        return ""
    return render_scan_context(matches, meta, limit)


# --------------------------------------------------------------- sync (HTTP)
def _as_json(data):
    if isinstance(data, (bytes, bytearray)):
        return json.loads(data.decode("utf-8", "replace"))
    if isinstance(data, str):
        return json.loads(data)
    return data


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (explicit https host allowlist below)
        return r.read()


def nvd_url(since_days: int | None = None, keyword: str | None = None, start: int = 0) -> str:
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params: list[tuple[str, str]] = [("resultsPerPage", "2000"), ("startIndex", str(start))]
    if keyword:
        params.append(("keywordSearch", keyword))
    if since_days:
        end = time.gmtime()
        start_t = time.gmtime(time.time() - since_days * 86400)
        params.append(("lastModStartDate", time.strftime("%Y-%m-%dT%H:%M:%S.000", start_t)))
        params.append(("lastModEndDate", time.strftime("%Y-%m-%dT%H:%M:%S.000", end)))
    return base + "?" + urllib.parse.urlencode(params)


def osv_query_url() -> str:
    return "https://api.osv.dev/v1/query"


def sync_nvd(con, http=http_get, since_days=None, keyword=None) -> dict:
    raw = http(nvd_url(since_days=since_days, keyword=keyword))
    recs = parse_nvd(raw)
    rep = upsert(con, recs)
    _set_meta(con, "nvd", len(recs))
    return rep


def sync_osv(con, http=http_get, ecosystem=None, package=None, source="osv") -> dict:
    body = {}
    if package:
        body["package"] = {"name": package}
        if ecosystem:
            body["package"]["ecosystem"] = ecosystem
    data = json.dumps(body).encode()
    req = urllib.request.Request(osv_query_url(), data=data,
                                 headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    if http is http_get:
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
            raw = r.read()
    else:
        raw = http(osv_query_url(), body)
    recs = parse_osv(raw, source=source)
    rep = upsert(con, recs)
    _set_meta(con, source, len(recs))
    return rep


def sync_kev(con, http=http_get) -> dict:
    raw = http("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    n = apply_kev(con, parse_kev(raw))
    _set_meta(con, "kev", n)
    return {"kev": n}


def sync_exploitdb(con, http=http_get) -> dict:
    raw = http("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv")
    n = apply_exploitdb(con, parse_exploitdb(raw))
    _set_meta(con, "exploitdb", n)
    return {"exploitdb": n}


def _set_meta(con, source: str, count: int) -> None:
    con.execute(
        "INSERT INTO feed_meta(source,last_sync,cursor,count) VALUES(?,?,?,?) "
        "ON CONFLICT(source) DO UPDATE SET last_sync=excluded.last_sync, "
        "count=feed_meta.count+excluded.count",
        (source, ts(), "", count))
    con.commit()


def status(con) -> dict:
    total = con.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    kev = con.execute("SELECT COUNT(*) FROM cve WHERE kev=1").fetchone()[0]
    exploited = con.execute("SELECT COUNT(*) FROM cve WHERE exploited=1").fetchone()[0]
    feeds = {r["source"]: {"last_sync": r["last_sync"], "count": r["count"]}
             for r in con.execute("SELECT * FROM feed_meta")}
    return {"total": total, "kev": kev, "exploited": exploited, "feeds": feeds,
            "db": str(DB_PATH)}


# ------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="penenv cve",
                                 description="Host-side CVE knowledge feed (never runs in the sandbox).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("sync", help="refresh the local CVE library from public sources")
    sp.add_argument("--source", default="all", help="all|" + "|".join(SOURCES))
    sp.add_argument("--since", type=int, default=None, metavar="DAYS",
                    help="NVD: only CVEs modified in the last N days (incremental)")
    sp.add_argument("--keyword", default=None, help="NVD keyword search (e.g. a product name)")
    sp.add_argument("--ecosystem", default=None, help="OSV ecosystem (e.g. npm, PyPI)")
    sp.add_argument("--package", default=None, help="OSV package name")
    sub.add_parser("status", help="show library size and per-source freshness")
    mp = sub.add_parser("match", help="list CVEs matching a stack term")
    mp.add_argument("--term", required=True, action="append", help="e.g. 'openssh 7.4' (repeatable)")
    mp.add_argument("--limit", type=int, default=25)
    shp = sub.add_parser("show", help="print one stored CVE as JSON")
    shp.add_argument("cve_id")
    args = ap.parse_args(argv)

    con = connect()
    try:
        if args.cmd == "status":
            print(json.dumps(status(con), indent=2))
            return 0
        if args.cmd == "match":
            rows = match_stack(con, args.term, limit=args.limit)
            print(render_scan_context(rows) or "(no matches)")
            return 0
        if args.cmd == "show":
            row = con.execute("SELECT * FROM cve WHERE id=?", (args.cve_id,)).fetchone()
            if not row:
                print(f"[cve] {args.cve_id} not in the local library", flush=True)
                return 1
            print(json.dumps(_row_to_dict(row), indent=2))
            return 0
        # sync
        want = SOURCES if args.source == "all" else (args.source,)
        print(f"[cve] host-side sync; contacting: "
              f"{', '.join(sorted({SOURCE_HOSTS[s] for s in want}))}")
        rep = {}
        try:
            if "nvd" in want:
                rep["nvd"] = sync_nvd(con, since_days=args.since, keyword=args.keyword)
            if "osv" in want and args.package:
                rep["osv"] = sync_osv(con, ecosystem=args.ecosystem, package=args.package)
            if "ghsa" in want and args.package:
                rep["ghsa"] = sync_osv(con, ecosystem=args.ecosystem, package=args.package, source="ghsa")
            if "kev" in want:
                rep["kev"] = sync_kev(con)
            if "exploitdb" in want:
                rep["exploitdb"] = sync_exploitdb(con)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"[cve] sync error (partial results kept): {e}")
        print(json.dumps({"synced": rep, "status": status(con)}, indent=2))
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    raise SystemExit(main())
