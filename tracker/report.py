"""penenv penetration-test report generator.

Turns a completed Strix run (strix_runs/<run>/{run.json,vulnerabilities.json}) into a
polished, readable, actionable pen-test report with a cover page, contents, executive
summary with a severity breakdown and top risks, detailed findings grouped by severity,
and an appendix grouping the findings by type (CWE) — every finding carrying its code
snippet (PoC) and a proposed correction.

Outputs, driven by the editable template report_template.html:
  * HTML  — self-contained, styled for screen and print.
  * PDF   — rendered from the HTML with headless Chromium (--print-to-pdf).
  * DOCX  — converted from the HTML with LibreOffice (soffice --convert-to docx).

No third-party Python packages are required; the toolchain is Chromium + LibreOffice,
both already present. Markdown inside finding fields is rendered by a small, safe subset
renderer below (fenced code, inline code, bold, lists, headings, paragraphs).

CLI:
  python3 tracker/report.py --run <run_dir|run_id> [--out DIR] [--formats html,pdf,docx]
  python3 tracker/report.py --project NAME [--latest] [--run-id ID] [--out DIR] ...
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STRIX_RUNS = ROOT / "strix_runs"
TEMPLATE = Path(__file__).resolve().parent / "report_template.html"
TEMPLATE_DOCX = Path(__file__).resolve().parent / "report_template_docx.html"
BRAND = "penenv Security"

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


# --------------------------------------------------------------------------- #
#  tiny, safe markdown subset  ->  html
# --------------------------------------------------------------------------- #
def _esc(s: str) -> str:
    return html.escape(str(s), quote=False)


def _inline(s: str) -> str:
    s = _esc(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<!\*)\*(?!\*)([^*\n]+?)\*(?!\*)", r"<em>\1</em>", s)
    return s


def md_to_html(text: str) -> str:
    """Render a safe subset: ``` fenced code, headings, -/* and n. lists, **bold**, `code`."""
    if text is None:
        return ""
    lines = str(text).replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i, n = 0, len(lines)
    para: list[str] = []
    list_stack: str | None = None

    def flush_para():
        nonlocal para
        if para:
            out.append("<p>" + "<br>".join(_inline(x) for x in para) + "</p>")
            para = []

    def close_list():
        nonlocal list_stack
        if list_stack:
            out.append(f"</{list_stack}>")
            list_stack = None

    while i < n:
        line = lines[i]
        fence = re.match(r"^\s*```+\s*([\w+-]*)\s*$", line)
        if fence:
            flush_para(); close_list()
            buf = []
            i += 1
            while i < n and not re.match(r"^\s*```+\s*$", lines[i]):
                buf.append(lines[i]); i += 1
            i += 1  # skip closing fence
            out.append("<pre><code>" + _esc("\n".join(buf)) + "</code></pre>")
            continue
        h = re.match(r"^\s*(#{1,6})\s+(.*)$", line)
        if h:
            flush_para(); close_list()
            out.append(f"<h4>{_inline(h.group(2).strip())}</h4>")
            i += 1; continue
        ul = re.match(r"^\s*[-*]\s+(.*)$", line)
        ol = re.match(r"^\s*\d+[.)]\s+(.*)$", line)
        if ul or ol:
            flush_para()
            want = "ul" if ul else "ol"
            if list_stack and list_stack != want:
                close_list()
            if not list_stack:
                out.append(f"<{want}>"); list_stack = want
            out.append("<li>" + _inline((ul or ol).group(1).strip()) + "</li>")
            i += 1; continue
        if line.strip() == "":
            flush_para(); close_list()
            i += 1; continue
        para.append(line.strip())
        i += 1
    flush_para(); close_list()
    return "\n".join(out)


def _code_block(code: str) -> str:
    """Render a code field: honour an existing fence, else wrap verbatim."""
    if not code or not str(code).strip():
        return ""
    s = str(code)
    if "```" in s:
        return md_to_html(s)
    return "<pre><code>" + _esc(s.strip("\n")) + "</code></pre>"


# --------------------------------------------------------------------------- #
#  load + normalise
# --------------------------------------------------------------------------- #
def resolve_run(run: str) -> Path:
    p = Path(run)
    if p.is_dir():
        return p
    cand = STRIX_RUNS / run
    if cand.is_dir():
        return cand
    raise SystemExit(f"[report] no such run dir: {run}")


def latest_run_for(target_url: str | None = None, run_id: str | None = None) -> Path:
    if not STRIX_RUNS.is_dir():
        raise SystemExit("[report] no strix_runs/ directory yet")
    runs = [d for d in STRIX_RUNS.iterdir() if d.is_dir() and (d / "run.json").exists()]
    if run_id:
        runs = [d for d in runs if d.name == run_id]
    if target_url:
        def _hits(d):
            try:
                rj = json.loads((d / "run.json").read_text())
            except Exception:
                return False
            return any(target_url in (t.get("original") or "") for t in rj.get("targets_info", []))
        hit = [d for d in runs if _hits(d)]
        runs = hit or runs
    if not runs:
        raise SystemExit("[report] no matching completed runs found")
    runs.sort(key=lambda d: (d / "run.json").stat().st_mtime, reverse=True)
    return runs[0]


def _norm_sev(s: str) -> str:
    s = (s or "INFO").strip().upper()
    return s if s in SEV_RANK else "INFO"


def load_findings(run_dir: Path) -> list[dict]:
    vulns = []
    vj = run_dir / "vulnerabilities.json"
    if vj.exists():
        try:
            vulns = json.loads(vj.read_text()) or []
        except Exception as e:
            raise SystemExit(f"[report] cannot parse {vj}: {e}")
    norm = []
    for v in vulns:
        d = dict(v)
        d["severity"] = _norm_sev(d.get("severity"))
        try:
            d["_cvss"] = float(d.get("cvss")) if d.get("cvss") not in (None, "") else None
        except (TypeError, ValueError):
            d["_cvss"] = None
        d["cwe"] = (d.get("cwe") or "").strip() or "Unclassified"
        norm.append(d)
    norm.sort(key=lambda d: (SEV_RANK[d["severity"]], -(d["_cvss"] or 0)))
    return norm


def load_run_meta(run_dir: Path) -> dict:
    rj = {}
    f = run_dir / "run.json"
    if f.exists():
        try:
            rj = json.loads(f.read_text())
        except Exception:
            rj = {}
    targets = [t.get("original") or t.get("details", {}).get("target_url", "")
               for t in rj.get("targets_info", [])]
    return {
        "run_id": rj.get("run_id") or run_dir.name,
        "status": rj.get("status") or "unknown",
        "start": rj.get("start_time") or "",
        "end": rj.get("end_time") or "",
        "targets": [t for t in targets if t],
        "auth_mode": rj.get("auth_mode") or "",
    }


def _fmt_dt(iso: str) -> str:
    if not iso:
        return "—"
    try:
        d = _dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return d.strftime("%d %b %Y %H:%M UTC")
    except Exception:
        return iso


def read_exec_summary_md(run_dir: Path) -> str:
    """Prefer Strix's own well-written Executive Summary prose, if the markdown report has one."""
    for name in ("penetration_test_report.md", "report.md"):
        p = run_dir / name
        if not p.exists():
            continue
        txt = p.read_text()
        m = re.search(r"^#+\s*Executive Summary\s*$(.*?)(?=^#+\s|\Z)", txt,
                      re.MULTILINE | re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


# --------------------------------------------------------------------------- #
#  model
# --------------------------------------------------------------------------- #
def build_model(run_dir: Path, project: dict | None, title: str | None) -> dict:
    meta = load_run_meta(run_dir)
    findings = load_findings(run_dir)
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    by_type: dict[str, list[dict]] = {}
    for f in findings:
        by_type.setdefault(f["cwe"], []).append(f)
    top = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:6]
    if len(top) < 5:
        top = findings[:5]
    eng = project or {}
    tgt = meta["targets"][0] if meta["targets"] else (
        (eng.get("endpoints") or [{}])[0].get("data", "—"))
    return {
        "title": title or "Penetration Test Report",
        "meta": meta,
        "findings": findings,
        "counts": counts,
        "total": len(findings),
        "by_type": by_type,
        "top": top,
        "target": tgt,
        "project": eng,
        "exec_md": read_exec_summary_md(run_dir),
    }


# --------------------------------------------------------------------------- #
#  render
# --------------------------------------------------------------------------- #
def _sev_badge(sev: str) -> str:
    return f'<span class="badge sev-{sev.lower()}">{sev}</span>'


def _anchor(s: str) -> str:
    return "f-" + re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def render_cover(m: dict) -> str:
    eng = m["project"]
    hat = (eng.get("hat") or "").title()
    pos = (eng.get("position") or "").title()
    agg = eng.get("aggression")
    level = {1: "L1 Light", 2: "L2 Standard", 3: "L3 Aggressive", 4: "L4 Very aggressive"}.get(agg, "")
    scope_bits = " · ".join(x for x in [hat and f"{hat} hat", pos and f"{pos}", level] if x)
    name = eng.get("name") or m["meta"]["run_id"]
    return f"""
<section class="cover">
  <div>
    <div class="mark">{_esc(BRAND)}</div>
    <div class="ttl">{_esc(m['title'])}</div>
    <div class="sub">{_esc(name)}</div>
    <span class="classif">Confidential</span>
  </div>
  <div>
    <dl>
      <dt>Target</dt><dd>{_esc(m['target'])}</dd>
      <dt>Engagement</dt><dd>{_esc(scope_bits or 'Authorised security assessment')}</dd>
      <dt>Tested</dt><dd>{_esc(_fmt_dt(m['meta']['start']))} &nbsp;→&nbsp; {_esc(_fmt_dt(m['meta']['end']))}</dd>
      <dt>Findings</dt><dd>{m['total']} confirmed
        ({m['counts']['CRITICAL']} Critical, {m['counts']['HIGH']} High,
         {m['counts']['MEDIUM']} Medium, {m['counts']['LOW']} Low)</dd>
      <dt>Run ID</dt><dd>{_esc(m['meta']['run_id'])}</dd>
    </dl>
  </div>
  <div class="foot">
    Prepared by {_esc(BRAND)} · Generated {{{{GENERATED}}}}<br>
    This document contains confidential findings. Handle, store and distribute on a need-to-know basis.
  </div>
</section>"""


def render_toc(m: dict) -> str:
    items = [
        ("1", "Executive Summary", "sec-exec", False),
        ("2", "Scope &amp; Methodology", "sec-scope", False),
        ("3", "Detailed Findings", "sec-findings", False),
    ]
    sub = []
    for sev in SEV_ORDER:
        if m["counts"][sev]:
            sub.append((f"{sev.title()} ({m['counts'][sev]})", "sec-" + sev.lower()))
    apx = [
        ("A", "Appendix A — Findings by Type (CWE)", "apx-type"),
        ("B", "Appendix B — Finding Index &amp; Severity Model", "apx-index"),
    ]
    rows = []
    for num, label, aid, _ in items:
        rows.append(f'<li><span class="n">{num}</span><span class="t">'
                    f'<a href="#{aid}">{label}</a></span><span class="dots"></span></li>')
        if aid == "sec-findings":
            for label2, aid2 in sub:
                rows.append(f'<li class="sub"><span class="t"><a href="#{aid2}">{label2}</a>'
                            f'</span><span class="dots"></span></li>')
    for num, label, aid in apx:
        rows.append(f'<li><span class="n">{num}</span><span class="t">'
                    f'<a href="#{aid}">{label}</a></span><span class="dots"></span></li>')
    return ('<section class="page-break"><h1>Contents</h1><ul class="toc">'
            + "\n".join(rows) + "</ul></section>")


def render_severity_summary(m: dict) -> str:
    cards = ""
    for sev in SEV_ORDER:
        cards += (f'<div class="sevcard {sev.lower()}"><div class="n">{m["counts"][sev]}</div>'
                  f'<div class="l">{sev.title()}</div></div>')
    total = max(m["total"], 1)
    bar = ""
    for sev in SEV_ORDER:
        c = m["counts"][sev]
        if c:
            bar += f'<span class="b-{sev.lower()}" style="width:{c/total*100:.4f}%"></span>'
    return f'<div class="sevgrid">{cards}</div><div class="bar">{bar}</div>'


def render_top_risks(m: dict) -> str:
    if not m["top"]:
        return ""
    rows = ""
    for i, f in enumerate(m["top"], 1):
        cvss = f'{f["_cvss"]:.1f}' if f["_cvss"] is not None else "—"
        rows += (f"<tr><td>{i}</td><td>{_sev_badge(f['severity'])}</td>"
                 f'<td class="cvss">{cvss}</td>'
                 f'<td><a href="#{_anchor(f.get("id","")+f.get("title",""))}">{_esc(f.get("title",""))}</a></td>'
                 f"<td>{_esc(f.get('cwe',''))}</td></tr>")
    return ("<h3>Top risks</h3><table><thead><tr><th>#</th><th>Severity</th><th>CVSS</th>"
            "<th>Finding</th><th>Type</th></tr></thead><tbody>" + rows + "</tbody></table>")


def render_exec(m: dict) -> str:
    if m["exec_md"]:
        prose = md_to_html(m["exec_md"])
    else:
        c = m["counts"]
        prose = (f"<p>This assessment of <code>{_esc(m['target'])}</code> identified "
                 f"<strong>{m['total']} confirmed finding(s)</strong>: "
                 f"{c['CRITICAL']} Critical, {c['HIGH']} High, {c['MEDIUM']} Medium, "
                 f"{c['LOW']} Low and {c['INFO']} Informational. "
                 "Each finding below was reproduced with a working proof of concept and is "
                 "accompanied by a proposed correction.</p>")
    return (f'<section class="page-break" id="sec-exec"><h2>1 &nbsp; Executive Summary</h2>'
            f"{render_severity_summary(m)}{prose}{render_top_risks(m)}</section>")


def render_scope(m: dict) -> str:
    eng = m["project"]
    meta = m["meta"]
    rows = [("Target(s)", ", ".join(meta["targets"]) or m["target"])]
    if eng.get("hat"):
        rows.append(("Knowledge level", f"{eng['hat'].title()} hat"))
    if eng.get("position"):
        rows.append(("Test position", eng["position"].title()))
    if eng.get("aggression"):
        rows.append(("Aggressiveness", {1: "L1 Light", 2: "L2 Standard", 3: "L3 Aggressive",
                                         4: "L4 Very aggressive"}.get(eng["aggression"], str(eng["aggression"]))))
    if eng.get("approach"):
        rows.append(("Methodology", eng["approach"]))
    rows.append(("Window", _fmt_dt(meta["start"]) + " → " + _fmt_dt(meta["end"])))
    rows.append(("Engagement status", meta["status"]))
    oos = eng.get("out_of_scope") or []
    if oos:
        rows.append(("Explicitly out of scope", ", ".join(x.get("data", "") for x in oos)))
    body = "".join(f'<tr><th style="width:190px">{_esc(k)}</th><td>{_esc(v)}</td></tr>' for k, v in rows)
    note = ("<div class=\"callout small\">Testing was time-boxed and authorised. Findings reflect "
            "demonstrated exploitability against the scope above; absence of a finding is not proof "
            "of absence of risk. All proof-of-concept activity stopped at proof and avoided "
            "destructive or denial-of-service actions.</div>")
    return (f'<section class="page-break" id="sec-scope"><h2>2 &nbsp; Scope &amp; Methodology</h2>'
            f"<table>{body}</table>{note}</section>")


def _finding_meta_items(f: dict) -> list[tuple[str, str]]:
    cvss = f'{f["_cvss"]:.1f}' if f["_cvss"] is not None else "—"
    items = [
        ("Severity", _sev_badge(f["severity"])),
        ("CVSS", f'<span class="cvss">{cvss}</span>'),
        ("Type", _esc(f.get("cwe", ""))),
        ("Confidence", _esc((f.get("confidence") or "").title())),
        ("Fix effort", _esc((f.get("fix_effort") or "").title())),
    ]
    loc = ((f.get("method") or "") + " " + (f.get("endpoint") or "")).strip() or f.get("target", "")
    if loc:
        items.append(("Location", f"<code>{_esc(loc)}</code>"))
    return items


def _finding_sections(f: dict) -> list[tuple[str, str]]:
    """Shared, ordered (title, html) content sections for one finding."""
    return [(t, h) for t, h in [
        ("Description", md_to_html(f.get("description", ""))),
        ("Impact", md_to_html(f.get("impact", ""))),
        ("Technical analysis", md_to_html(f.get("technical_analysis", ""))),
        ("Proof of concept", md_to_html(f.get("poc_description", ""))),
        ("Proof-of-concept code", _code_block(f.get("poc_script_code", ""))),
        ("Evidence", md_to_html(f.get("evidence", ""))),
        ("Proposed correction", md_to_html(f.get("remediation_steps", ""))),
    ] if h]


def render_finding(f: dict, idx: str) -> str:
    anchor = _anchor(f.get("id", "") + f.get("title", ""))
    meta_html = "".join(f'<div><div class="k">{k}</div><div>{v}</div></div>'
                        for k, v in _finding_meta_items(f))
    body = "".join(f'<div class="fsec"><h4>{t}</h4>{h}</div>' for t, h in _finding_sections(f))
    return f"""
<div class="finding" id="{anchor}">
  <div class="head">
    <span class="fid">{_esc(idx)}</span>{_sev_badge(f['severity'])}
    <span class="name">{_esc(f.get('title',''))}</span>
  </div>
  <div class="body">
    <div class="meta">{meta_html}</div>
    {body}
  </div>
</div>"""


def render_finding_docx(f: dict, idx: str) -> str:
    """Document-flow finding for Word: heading + metadata table + labelled sections."""
    rows = "".join(f'<tr><th style="width:150px">{k}</th><td>{v}</td></tr>'
                   for k, v in _finding_meta_items(f))
    body = "".join(f"<h4>{t}</h4>{h}" for t, h in _finding_sections(f))
    return (f'<h3>[{_esc(idx)}] {_esc(f.get("title",""))}</h3>'
            f"<table>{rows}</table>{body}")


def render_findings(m: dict) -> str:
    if not m["findings"]:
        return ('<section class="page-break" id="sec-findings"><h2>3 &nbsp; Detailed Findings</h2>'
                '<div class="callout">No vulnerabilities were confirmed within the test scope and '
                'time-box. This is not a guarantee that the application is free of defects.</div></section>')
    out = ['<section class="page-break" id="sec-findings"><h2>3 &nbsp; Detailed Findings</h2>'
           '<p class="muted small">Findings are ordered by severity, then CVSS. Each carries a '
           'reproduction, a code-level proof of concept, and a proposed correction.</p>']
    counters = {s: 0 for s in SEV_ORDER}
    for sev in SEV_ORDER:
        group = [f for f in m["findings"] if f["severity"] == sev]
        if not group:
            continue
        out.append(f'<h3 id="sec-{sev.lower()}">{sev.title()} &nbsp;'
                   f'<span class="badge sev-{sev.lower()}">{len(group)}</span></h3>')
        for f in group:
            counters[sev] += 1
            out.append(render_finding(f, f"{sev[0]}{counters[sev]}"))
    out.append("</section>")
    return "".join(out)


def render_apx_type(m: dict) -> str:
    if not m["findings"]:
        return ""
    out = ['<section class="page-break" id="apx-type"><h2>Appendix A &nbsp; Findings by Type (CWE)</h2>'
           '<p class="muted small">The same findings grouped by weakness class, to show systemic '
           'themes and shared remediations.</p>']
    for cwe in sorted(m["by_type"], key=lambda c: (-len(m["by_type"][c]), c)):
        group = sorted(m["by_type"][cwe], key=lambda f: (SEV_RANK[f["severity"]], -(f["_cvss"] or 0)))
        rows = ""
        for f in group:
            cvss = f'{f["_cvss"]:.1f}' if f["_cvss"] is not None else "—"
            rows += (f"<tr><td>{_sev_badge(f['severity'])}</td><td class=\"cvss\">{cvss}</td>"
                     f'<td><a href="#{_anchor(f.get("id","")+f.get("title",""))}">'
                     f'{_esc(f.get("title",""))}</a></td></tr>')
        out.append(f'<h3>{_esc(cwe)} &nbsp;<span class="badge sev-info">{len(group)}</span></h3>'
                   "<table><thead><tr><th style=\"width:92px\">Severity</th>"
                   "<th style=\"width:60px\">CVSS</th><th>Finding</th></tr></thead><tbody>"
                   + rows + "</tbody></table>")
    out.append("</section>")
    return "".join(out)


def render_apx_index(m: dict) -> str:
    rows = ""
    counters = {s: 0 for s in SEV_ORDER}
    for sev in SEV_ORDER:
        for f in [x for x in m["findings"] if x["severity"] == sev]:
            counters[sev] += 1
            cvss = f'{f["_cvss"]:.1f}' if f["_cvss"] is not None else "—"
            rows += (f'<tr><td>{sev[0]}{counters[sev]}</td><td>{_sev_badge(sev)}</td>'
                     f'<td class="cvss">{cvss}</td>'
                     f'<td><a href="#{_anchor(f.get("id","")+f.get("title",""))}">'
                     f'{_esc(f.get("title",""))}</a></td><td>{_esc(f.get("cwe",""))}</td></tr>')
    index = ("<h3>Finding index</h3><table><thead><tr><th>Ref</th><th>Severity</th><th>CVSS</th>"
             "<th>Finding</th><th>Type</th></tr></thead><tbody>" + rows + "</tbody></table>") if rows else ""
    model = ("<h3>Severity model</h3>"
             "<table><thead><tr><th>Severity</th><th>Typical CVSS</th><th>Meaning</th></tr></thead><tbody>"
             "<tr><td>" + _sev_badge("CRITICAL") + "</td><td>9.0–10.0</td>"
             "<td>Direct, low-effort path to full compromise or mass data loss; fix immediately.</td></tr>"
             "<tr><td>" + _sev_badge("HIGH") + "</td><td>7.0–8.9</td>"
             "<td>Serious exposure, readily exploitable; fix within days.</td></tr>"
             "<tr><td>" + _sev_badge("MEDIUM") + "</td><td>4.0–6.9</td>"
             "<td>Meaningful risk, usually needing a precondition or chaining; fix within weeks.</td></tr>"
             "<tr><td>" + _sev_badge("LOW") + "</td><td>0.1–3.9</td>"
             "<td>Limited impact or hard to exploit; fix as hygiene.</td></tr>"
             "<tr><td>" + _sev_badge("INFO") + "</td><td>—</td>"
             "<td>No direct risk; hardening or observation.</td></tr></tbody></table>")
    return (f'<section class="page-break" id="apx-index"><h2>Appendix B &nbsp; Finding Index &amp; '
            f'Severity Model</h2>{index}{model}</section>')


def _fill(tpl_path: Path, body: str, m: dict) -> str:
    gen = _dt.datetime.now(_dt.timezone.utc).strftime("%d %b %Y %H:%M UTC")
    tpl = re.sub(r"<!--.*?-->", "", tpl_path.read_text(), flags=re.DOTALL)  # drop comments (may hold tokens)
    full = tpl.replace("{{CONTENT}}", body)  # body first so its tokens fill too
    return (full.replace("{{TITLE}}", _esc(m["title"]))
                .replace("{{BRAND}}", _esc(BRAND))
                .replace("{{GENERATED}}", gen))


def render_html(m: dict) -> str:
    body = (render_cover(m) + '<div class="page">' + render_toc(m) + render_exec(m)
            + render_scope(m) + render_findings(m) + render_apx_type(m)
            + render_apx_index(m) + "</div>")
    return _fill(TEMPLATE, body, m)


def _severity_table(m: dict) -> str:
    rows = "".join(f"<tr><td>{_sev_badge(s)}</td><td>{m['counts'][s]}</td></tr>" for s in SEV_ORDER)
    return ("<table><thead><tr><th style=\"width:120px\">Severity</th><th>Count</th></tr></thead>"
            f"<tbody>{rows}<tr><th>Total</th><th>{m['total']}</th></tr></tbody></table>")


def render_docx_html(m: dict) -> str:
    """Word-optimised, document-flow variant: text cover, tables instead of flex/grid."""
    eng = m["project"]
    scope_bits = " · ".join(x for x in [
        (eng.get("hat") or "") and f"{eng['hat'].title()} hat",
        (eng.get("position") or "").title(),
        {1: "L1", 2: "L2", 3: "L3", 4: "L4"}.get(eng.get("aggression"), "")] if x)
    cover = (f'<p class="muted">{_esc(BRAND)}</p>'
             f'<div class="cover-ttl">{_esc(m["title"])}</div>'
             f'<div class="cover-sub">{_esc(eng.get("name") or m["meta"]["run_id"])} — Confidential</div>'
             "<table>"
             f'<tr><th style="width:150px">Target</th><td>{_esc(m["target"])}</td></tr>'
             f'<tr><th>Engagement</th><td>{_esc(scope_bits or "Authorised security assessment")}</td></tr>'
             f'<tr><th>Tested</th><td>{_esc(_fmt_dt(m["meta"]["start"]))} → {_esc(_fmt_dt(m["meta"]["end"]))}</td></tr>'
             f'<tr><th>Run ID</th><td>{_esc(m["meta"]["run_id"])}</td></tr>'
             "</table>")
    exec_body = md_to_html(m["exec_md"]) if m["exec_md"] else (
        f"<p>This assessment of <code>{_esc(m['target'])}</code> confirmed "
        f"<strong>{m['total']}</strong> finding(s). Each is reproduced below with a "
        "proof of concept and a proposed correction.</p>")
    exec_sec = (f"<h2>1 &nbsp; Executive Summary</h2>{_severity_table(m)}"
                f"{exec_body}{render_top_risks(m)}")
    findings = ["<h2>3 &nbsp; Detailed Findings</h2>"]
    if not m["findings"]:
        findings.append("<p>No vulnerabilities were confirmed within the test scope and time-box.</p>")
    else:
        counters = {s: 0 for s in SEV_ORDER}
        for sev in SEV_ORDER:
            group = [f for f in m["findings"] if f["severity"] == sev]
            if not group:
                continue
            findings.append(f"<h3>{sev.title()} ({len(group)})</h3>")
            for f in group:
                counters[sev] += 1
                findings.append(render_finding_docx(f, f"{sev[0]}{counters[sev]}"))
    body = (cover + exec_sec + render_scope(m).replace('<section class="page-break" id="sec-scope">', "<div>")
            + "".join(findings) + render_apx_type(m) + render_apx_index(m))
    # strip the <section ...> wrappers (page-break anchors) that Word doesn't need
    body = re.sub(r'<section[^>]*>', "<div>", body).replace("</section>", "</div>")
    return _fill(TEMPLATE_DOCX, body, m)


# --------------------------------------------------------------------------- #
#  format conversion
# --------------------------------------------------------------------------- #
def _chromium() -> str | None:
    for c in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if shutil.which(c):
            return c
    return None


def to_pdf(html_path: Path, pdf_path: Path) -> Path:
    exe = _chromium()
    if not exe:
        raise SystemExit("[report] no Chromium found for PDF rendering")
    prof = pdf_path.parent / ".chrome-prof"
    cmd = [exe, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
           f"--user-data-dir={prof}", "--no-pdf-header-footer",
           "--run-all-compositor-stages-before-draw", "--virtual-time-budget=12000",
           f"--print-to-pdf={pdf_path}", html_path.as_uri()]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if not pdf_path.exists() or pdf_path.stat().st_size == 0:
        raise SystemExit(f"[report] PDF render failed: {r.stderr[-400:]}")
    shutil.rmtree(prof, ignore_errors=True)
    return pdf_path


def to_docx(docx_html: str, docx_path: Path) -> Path:
    """Convert the Word-optimised HTML (document-flow, light CSS) to .docx via LibreOffice.
    The rich screen/print HTML is deliberately NOT used here — its flex/grid/gradient CSS
    makes LibreOffice's importer extremely slow; the document-flow variant converts in seconds."""
    exe = shutil.which("soffice") or shutil.which("libreoffice")
    if not exe:
        raise SystemExit("[report] no LibreOffice (soffice) found for DOCX conversion")
    # clear any stale LibreOffice lock from a previously killed run on this output name
    for lk in docx_path.parent.glob(".~lock.*#"):
        lk.unlink(missing_ok=True)
    src = docx_path.parent / (docx_path.stem + "__word.html")   # intermediate, removed after
    src.write_text(docx_html, encoding="utf-8")
    prof = docx_path.parent / ".lo-prof"
    cmd = [exe, "--headless", "--norestore", f"-env:UserInstallation={prof.as_uri()}",
           "--convert-to", "docx:MS Word 2007 XML", "--outdir", str(docx_path.parent), str(src)]
    subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    produced = docx_path.parent / (src.stem + ".docx")   # <stem>__word.html -> <stem>__word.docx
    if produced != docx_path and produced.exists():
        produced.replace(docx_path)
    src.unlink(missing_ok=True)
    shutil.rmtree(prof, ignore_errors=True)
    for junk in list(docx_path.parent.glob("lu*.tmp")) + list(docx_path.parent.glob(".~lock.*#")):
        junk.unlink(missing_ok=True)  # LibreOffice scratch/lock files
    if not docx_path.exists() or docx_path.stat().st_size == 0:
        raise SystemExit("[report] DOCX conversion failed (LibreOffice produced no file)")
    return docx_path


# --------------------------------------------------------------------------- #
#  orchestration
# --------------------------------------------------------------------------- #
def load_project_cfg(name: str) -> dict | None:
    """Best-effort: fetch a saved project's config from the running tracker for cover metadata."""
    try:
        import urllib.request
        base = "http://127.0.0.1:8766"
        data = json.loads(urllib.request.urlopen(base + "/api/projects", timeout=5).read())
        projects = data.get("projects", data)
        match = [p for p in projects if p.get("name") == name]
        if not match:
            return {"name": name}
        pid = match[0]["id"]
        full = json.loads(urllib.request.urlopen(f"{base}/api/projects/{pid}", timeout=5).read())
        cfg = full.get("config", {})
        cfg["name"] = full.get("name", name)
        return cfg
    except Exception:
        return {"name": name}


def generate(run_dir: Path, out_dir: Path, formats: list[str],
             project: dict | None = None, title: str | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    m = build_model(run_dir, project, title)
    stem = "pentest-report-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", m["meta"]["run_id"])
    html_path = out_dir / (stem + ".html")
    html_path.write_text(render_html(m), encoding="utf-8")
    produced = {"html": str(html_path)}
    if "pdf" in formats:
        produced["pdf"] = str(to_pdf(html_path, out_dir / (stem + ".pdf")))
    if "docx" in formats:
        produced["docx"] = str(to_docx(render_docx_html(m), out_dir / (stem + ".docx")))
    produced["_model"] = {"total": m["total"], "counts": m["counts"], "run_id": m["meta"]["run_id"]}
    return produced


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="penenv report",
                                 description="Generate a pen-test report (HTML/PDF/DOCX) from a Strix run.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--run", help="run dir path or run id under strix_runs/")
    g.add_argument("--project", help="saved project name (uses its latest run unless --run-id given)")
    ap.add_argument("--run-id", help="with --project: pick this exact run id")
    ap.add_argument("--latest", action="store_true", help="with --project: use the most recent run (default)")
    ap.add_argument("--out", default=str(ROOT / "reports"), help="output directory")
    ap.add_argument("--formats", default="html,pdf,docx", help="comma list: html,pdf,docx")
    ap.add_argument("--title", default=None, help="report title (default: 'Penetration Test Report')")
    args = ap.parse_args(argv)

    project = None
    if args.run:
        run_dir = resolve_run(args.run)
    else:
        project = load_project_cfg(args.project)
        tgt = None
        if project and project.get("endpoints"):
            tgt = (project["endpoints"][0] or {}).get("data")
        run_dir = latest_run_for(target_url=tgt, run_id=args.run_id)

    formats = [x.strip().lower() for x in args.formats.split(",") if x.strip()]
    out = generate(run_dir, Path(args.out), formats, project=project, title=args.title)
    print(json.dumps({k: v for k, v in out.items() if not k.startswith("_")}, indent=2))
    mod = out["_model"]
    print(f"[report] {mod['run_id']}: {mod['total']} findings "
          f"({', '.join(f'{k.title()} {v}' for k, v in mod['counts'].items() if v)})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
