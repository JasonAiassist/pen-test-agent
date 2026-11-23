"""Engagement authorisation records — the contract gate for research mode.

Research mode (hypothesis-driven vulnerability chaining and unknown-flaw discovery)
is powerful and must never run outside a sanctioned engagement. This module decides,
fail-closed, whether a given scan may use research mode:

  * Lab / internal-only research (every in-scope target internal, no destructive/DoS):
    a lightweight *self-authorisation* is enough — any non-empty `authorisation`
    reference on the project. Nothing leaves the lab, so a signed contract is not
    required to experiment against targets you own.

  * External targets, destructive payloads, or DoS under research mode:
    require a *structured* authorisation record — a row in the tracker database's
    `authorisations` table, filled in on the dashboard's Authorisations tab — that is
    active (not revoked), unexpired, flagged to permit what the scan asks for
    (research_allowed / destructive_allowed), and whose scope covers every in-scope
    target. A free-text reference with no matching record is refused for these.

Every create / update / revoke is written to `authorisation_audit`. Rows are never
deleted, only revoked, so the contract trail behind past scans survives.

Stdlib-only. Every decision is a pure function of (record, scan parameters, today),
so it is fully unit-tested offline. Record fields:
    {ref, client, contract_ref, authorised_by, expires: "YYYY-MM-DD",
     research_allowed: bool, destructive_allowed: bool,
     scope: [ {type,data} ], notes}
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sqlite3
import time
from pathlib import Path

import scope

ROOT = Path(__file__).resolve().parents[1]
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,79}$")
FIELDS = ("ref", "client", "contract_ref", "authorised_by", "expires",
          "research_allowed", "destructive_allowed", "scope", "notes")


def _today() -> _dt.date:
    return _dt.date.today()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def default_db_path() -> Path:
    env = os.environ.get("PENENV_DB")
    return Path(env) if env else ROOT / "tracker" / "penenv.db"


# ------------------------------------------------------------------ storage
def ensure_table(con: sqlite3.Connection) -> None:
    con.execute(
        """CREATE TABLE IF NOT EXISTS authorisations(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               ref TEXT NOT NULL UNIQUE,
               client TEXT NOT NULL DEFAULT '',
               contract_ref TEXT NOT NULL DEFAULT '',
               authorised_by TEXT NOT NULL DEFAULT '',
               expires TEXT NOT NULL DEFAULT '',
               research_allowed INTEGER NOT NULL DEFAULT 0,
               destructive_allowed INTEGER NOT NULL DEFAULT 0,
               scope TEXT NOT NULL DEFAULT '[]',
               notes TEXT NOT NULL DEFAULT '',
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               revoked_at TEXT
           )""")
    con.execute(
        """CREATE TABLE IF NOT EXISTS authorisation_audit(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               auth_id INTEGER NOT NULL,
               ref TEXT NOT NULL,
               action TEXT NOT NULL,
               detail TEXT,
               at TEXT NOT NULL
           )""")
    con.commit()


def normalise_ref(ref: str) -> str:
    ref = (ref or "").strip()
    return ref[1:].strip() if ref.startswith("@") else ref


def parse_record(data: dict, ref: str = "") -> dict:
    """Normalise a raw record dict. Unknown/missing flags default to the safe value (False)."""
    scope_raw = data.get("scope") or []
    if isinstance(scope_raw, str):
        try:
            scope_raw = json.loads(scope_raw)
        except ValueError:
            scope_raw = []
    scope_entries = []
    for e in scope_raw if isinstance(scope_raw, list) else []:
        if isinstance(e, dict) and str(e.get("data") or "").strip():
            d = str(e["data"]).strip()
            scope_entries.append({"type": e.get("type") or (scope.infer_type(d) or ""), "data": d})
        elif isinstance(e, str) and e.strip():
            scope_entries.append({"type": scope.infer_type(e.strip()) or "", "data": e.strip()})
    return {
        "ref": normalise_ref(str(data.get("ref") or ref or "")),
        "client": str(data.get("client") or "").strip(),
        "contract_ref": str(data.get("contract_ref") or "").strip(),
        "authorised_by": str(data.get("authorised_by") or "").strip(),
        "expires": str(data.get("expires") or "").strip(),
        "research_allowed": data.get("research_allowed") in (True, 1, "1", "true", "on"),
        "destructive_allowed": data.get("destructive_allowed") in (True, 1, "1", "true", "on"),
        "scope": scope_entries,
        "notes": str(data.get("notes") or "").strip(),
        "inline": False,
    }


def validate_record(rec: dict) -> list[str]:
    """Problems that stop a record being saved (the dashboard shows these)."""
    errs = []
    if not REF_RE.match(rec.get("ref") or ""):
        errs.append("reference must be 1–80 characters: letters, digits, . _ / - (starting with a letter or digit)")
    if not rec.get("client"):
        errs.append("client is required")
    if not rec.get("authorised_by"):
        errs.append("authorised by (the signatory) is required")
    exp = rec.get("expires") or ""
    if exp:
        try:
            _dt.date.fromisoformat(exp)
        except ValueError:
            errs.append("expiry must be a date in YYYY-MM-DD form")
    if (rec.get("research_allowed") or rec.get("destructive_allowed")) and not exp:
        errs.append("an expiry date is required when research or destructive testing is permitted")
    if (rec.get("research_allowed") or rec.get("destructive_allowed")) and not rec.get("contract_ref"):
        errs.append("a contract / SOW reference is required when research or destructive testing is permitted")
    for i, e in enumerate(rec.get("scope") or []):
        msg = scope.validate_endpoint(e.get("type"), e.get("data"))
        if msg:
            errs.append(f"scope entry {i + 1} ({e.get('data')}): {msg}")
    return errs


def _row_to_record(row) -> dict:
    d = dict(row)
    rec = parse_record(d)
    rec.update({"id": d["id"], "created_at": d["created_at"], "updated_at": d["updated_at"],
                "revoked_at": d.get("revoked_at")})
    return rec


def _audit(con, auth_id: int, ref: str, action: str, detail: str = "") -> None:
    con.execute("INSERT INTO authorisation_audit(auth_id,ref,action,detail,at) VALUES(?,?,?,?,?)",
                (auth_id, ref, action, detail, _now()))


def list_records(con) -> list[dict]:
    ensure_table(con)
    con.row_factory = sqlite3.Row
    return [_row_to_record(r) for r in con.execute(
        "SELECT * FROM authorisations ORDER BY revoked_at IS NOT NULL, ref")]


def get_record(con, ref: str) -> dict | None:
    ensure_table(con)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM authorisations WHERE ref=?", (normalise_ref(ref),)).fetchone()
    return _row_to_record(row) if row else None


def save_record(con, data: dict, auth_id: int | None = None) -> tuple[dict | None, list[str]]:
    """Create (auth_id None) or update a record. Returns (record, errors)."""
    ensure_table(con)
    rec = parse_record(data)
    errs = validate_record(rec)
    if errs:
        return None, errs
    con.row_factory = sqlite3.Row
    clash = con.execute("SELECT id FROM authorisations WHERE ref=?", (rec["ref"],)).fetchone()
    if clash and clash["id"] != auth_id:
        return None, [f"an authorisation with reference {rec['ref']!r} already exists"]
    vals = (rec["ref"], rec["client"], rec["contract_ref"], rec["authorised_by"], rec["expires"],
            int(rec["research_allowed"]), int(rec["destructive_allowed"]),
            json.dumps(rec["scope"]), rec["notes"])
    now = _now()
    if auth_id is None:
        cur = con.execute(
            "INSERT INTO authorisations(ref,client,contract_ref,authorised_by,expires,research_allowed,"
            "destructive_allowed,scope,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            vals + (now, now))
        auth_id, action = cur.lastrowid, "create"
    else:
        old = con.execute("SELECT revoked_at FROM authorisations WHERE id=?", (auth_id,)).fetchone()
        if not old:
            return None, ["unknown authorisation"]
        if old["revoked_at"]:
            return None, ["a revoked authorisation cannot be edited — create a new one"]
        con.execute(
            "UPDATE authorisations SET ref=?,client=?,contract_ref=?,authorised_by=?,expires=?,"
            "research_allowed=?,destructive_allowed=?,scope=?,notes=?,updated_at=? WHERE id=?",
            vals + (now, auth_id))
        action = "update"
    _audit(con, auth_id, rec["ref"], action,
           json.dumps({"research_allowed": rec["research_allowed"],
                       "destructive_allowed": rec["destructive_allowed"],
                       "expires": rec["expires"], "scope": [e["data"] for e in rec["scope"]]}))
    con.commit()
    return _row_to_record(con.execute("SELECT * FROM authorisations WHERE id=?", (auth_id,)).fetchone()), []


def revoke_record(con, auth_id: int, reason: str = "") -> dict | None:
    ensure_table(con)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM authorisations WHERE id=?", (auth_id,)).fetchone()
    if not row:
        return None
    if not row["revoked_at"]:
        con.execute("UPDATE authorisations SET revoked_at=?, updated_at=? WHERE id=?", (_now(), _now(), auth_id))
        _audit(con, auth_id, row["ref"], "revoke", reason)
        con.commit()
    return _row_to_record(con.execute("SELECT * FROM authorisations WHERE id=?", (auth_id,)).fetchone())


def audit_trail(con, auth_id: int) -> list[dict]:
    ensure_table(con)
    con.row_factory = sqlite3.Row
    return [dict(r) for r in con.execute(
        "SELECT action, detail, at FROM authorisation_audit WHERE auth_id=? ORDER BY id", (auth_id,))]


def load_record(cfg: dict, con: sqlite3.Connection | None = None) -> dict | None:
    """Return the structured record named by the project's `authorisation` reference,
    an inline self-authorisation ({inline:True}) when no record has that reference,
    or None when no reference is set. Any database problem fails closed."""
    ref = normalise_ref(cfg.get("authorisation") or "")
    if not ref:
        return None
    inline = {"ref": ref, "inline": True, "scope": [], "research_allowed": False,
              "destructive_allowed": False, "expires": ""}
    own = con is None
    try:
        if own:
            con = sqlite3.connect(default_db_path(), timeout=30)
        rec = get_record(con, ref)
    except sqlite3.Error as e:
        return {**inline, "_error": f"authorisation database unreadable ({e})"}
    finally:
        if own and con is not None:
            con.close()
    if rec is None:
        return inline
    if rec.get("revoked_at"):
        rec["_error"] = f"authorisation {ref!r} was revoked on {rec['revoked_at']}"
    return rec


def _expired(record: dict, today: _dt.date) -> bool:
    exp = (record.get("expires") or "").strip()
    if not exp:
        return False  # no expiry set
    try:
        return _dt.date.fromisoformat(exp) < today
    except ValueError:
        return True  # an unparseable expiry is treated as expired (fail closed)


def _covers(record: dict, in_scope: list) -> list[str]:
    """Return the list of in-scope endpoint values NOT covered by the record's scope.
    Coverage is by normalised key equality, or an in-scope entry inside a scope CIDR."""
    import ipaddress

    keys, cidrs = set(), []
    for e in record.get("scope") or []:
        t, d = e.get("type"), e.get("data")
        if scope.validate_endpoint(t, d):
            continue
        keys.add(scope.norm_key(t, d))
        if t == "cidr":
            cidrs.append(ipaddress.ip_network(d, strict=False))
    uncovered = []
    for e in in_scope:
        if not isinstance(e, dict):
            continue
        t, d = e.get("type"), e.get("data")
        if scope.validate_endpoint(t, d):
            continue
        if scope.norm_key(t, d) in keys:
            continue
        covered = False
        if t in ("ip", "cidr") and cidrs:
            net = ipaddress.ip_network(d, strict=False)
            covered = any(net.subnet_of(c) for c in cidrs if c.version == net.version)
        if not covered:
            uncovered.append(d)
    return uncovered


def authorise_research(record: dict | None, *, position: str, destructive: bool,
                       dos: bool, in_scope: list, today: _dt.date | None = None) -> tuple[bool, list[str]]:
    """Decide, fail-closed, whether research mode may run. Returns (ok, reasons-if-refused)."""
    today = today or _today()
    if record is not None and record.get("_error"):
        return False, [record["_error"]]
    needs_contract = position in ("external", "both") or destructive or dos
    if not needs_contract:
        # Lab / internal-only, non-destructive: a self-authorisation reference suffices.
        if record is None:
            return False, ["research mode needs at least a self-authorisation reference "
                           "(set the project's authorisation field)"]
        return True, []
    # External / destructive / DoS research demands a structured contract record.
    errs: list[str] = []
    if record is None:
        return False, ["external or destructive research needs a structured authorisation record "
                       "(dashboard → Authorisations); no authorisation reference is set"]
    if record.get("inline"):
        return False, ["external or destructive research needs a structured authorisation record "
                       f"with reference {record.get('ref', 'REF')!r} (dashboard → Authorisations), "
                       "not just a free-text reference"]
    if not record.get("research_allowed"):
        errs.append("the authorisation record does not permit research mode (research_allowed=false)")
    if (destructive or dos) and not record.get("destructive_allowed"):
        errs.append("the authorisation record does not permit destructive/DoS testing "
                    "(destructive_allowed=false)")
    if _expired(record, today):
        errs.append(f"the authorisation expired on {record.get('expires')}")
    uncovered = _covers(record, in_scope or [])
    if uncovered:
        errs.append("these in-scope targets are not covered by the authorisation scope: "
                    + ", ".join(uncovered))
    return (not errs), errs
