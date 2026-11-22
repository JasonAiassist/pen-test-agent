# Pen-test reporting

Turns a completed Strix run into a polished, client-ready penetration-test report in
three formats. Built by `tracker/report.py`; driven by two editable templates.

## What the report contains

1. **Cover page** — title, engagement (hat / position / level), target, test window,
   finding tally, run id, confidentiality notice.
2. **Contents** — linked, with a sub-entry per severity present.
3. **Executive summary** — the assessment's narrative (reuses Strix's own executive
   prose when present), a severity breakdown (cards + bar), and a **Top risks** table.
4. **Scope & methodology** — targets, knowledge level, position, aggressiveness,
   methodology, window, explicit out-of-scope.
5. **Detailed findings** — grouped **by severity** (Critical → Info). Each finding shows
   CVSS, CWE, confidence, fix effort and location, then Description, Impact, Technical
   analysis, Proof of concept, **PoC code snippet**, Evidence, and **Proposed correction**.
6. **Appendix A — findings by type (CWE)** — the same findings regrouped by weakness
   class, to surface systemic themes.
7. **Appendix B — finding index & severity model.**

Kept readable and actionable: one card per finding, cross-linked, not padded.

## Formats & toolchain

| Format | How | Notes |
|--------|-----|-------|
| HTML   | self-contained, from `report_template.html` | screen + print CSS |
| PDF    | headless Chromium `--print-to-pdf` of the HTML | A4, running footer, page numbers |
| Word   | LibreOffice `--convert-to docx` of a **document-flow** variant (`report_template_docx.html`) | the rich flex/grid/gradient CSS makes LibreOffice's importer extremely slow, so Word uses a light, Word-safe variant with the same content |

No third-party Python packages are required. Markdown inside finding fields is rendered
by a small, safe subset renderer (fenced code, inline code, bold, lists, headings).

## Usage

```bash
penenv report --project <name>                       # latest run for the project
penenv report --project <name> --run-id <run_id>     # a specific run
penenv report --run <run_id> --formats html,pdf      # by run dir, chosen formats
penenv report --run <run_id> --out /tmp/out --title "Acme Q4 Assessment"
```

From the dashboard (`http://127.0.0.1:8766`), a **Generate pen-test report** button
appears when a scan finishes (New scan tab), on **Project → Scans & history**, and on
each run card on the Dashboard. It builds all three formats and shows download links.

Output goes to `reports/pentest-report-<run_id>.{html,pdf,docx}`.

## Endpoints

- `POST /api/projects/<id>/report` — build for the project's most recent matching run.
- `POST /api/run/<run_dir>/report` — build for an exact run.
  Body: `{"formats":["html","pdf","docx"], "title":"optional"}`.
  Returns `{run_id, model:{total,counts}, files:{html,pdf,docx}}` as `/api/reports/<name>` URLs.
- `GET /api/reports/<filename>` — download a generated file (basename only; no traversal).

## Rebranding / consistency

Edit the templates, not the generator:

- `tracker/report_template.html` — HTML/PDF look. Colours are CSS variables under
  `:root` (`--brand`, `--accent`, severity colours); the cover, footer and print `@page`
  rules live here.
- `tracker/report_template_docx.html` — the Word look (keep its CSS light so LibreOffice
  stays fast).
- `BRAND` in `tracker/report.py` sets the vendor/team name on the cover and footer.

Both templates expose the tokens `TITLE`, `BRAND`, `CONTENT`, `GENERATED` (each wrapped
in double braces). Tokens placed inside HTML comments are ignored.
