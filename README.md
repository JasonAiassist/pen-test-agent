# PenEnv — self-hosted SaaS penetration-test environment

Agent-driven penetration testing of your **own** SaaS applications using
[Strix](https://github.com/usestrix/strix) in its Docker sandbox, with a local
vulnerability tracker (dashboard, lifecycle, trends).

```
penenv/
├── bin/penenv              # CLI wrapper (strix, demo targets, tracker)
├── compose/targets/        # vulnerable demo apps (Juice Shop) for safe practice
├── profiles/               # OWASP SaaS-focused scan instructions
│   ├── auth-session.md     #   auth & session management
│   ├── access-control.md   #   IDOR/BOLA, privilege & tenant isolation
│   ├── injection.md        #   SQLi/NoSQL/XSS/SSTI/deserialization
│   ├── api-security.md     #   mass assignment, exposure, rate limits, CORS
│   ├── business-logic.md   #   price/workflow/quota/race abuse
│   ├── data-exposure.md    #   secrets, PII, enumeration, privacy
│   └── full-saas.md        #   all classes (default)
├── tracker/                # stdlib-only dashboard service
│   ├── ingest.py           #   strix_runs/ → findings DB (lifecycle tracking)
│   ├── server.py           #   http://127.0.0.1:8766
│   └── static/index.html
└── strix_runs/             # raw scan outputs (created by scans)
```

## Daily flow

```bash
penenv up                       # start Juice Shop (practice target)
penenv demo                     # quick end-to-end sanity scan + ingest
penenv tracker start            # dashboard at http://127.0.0.1:8766

# Policy-enforced scan driven by a Project page (recommended):
penenv scan --project <name> --dry-run          # print the fully resolved plan, secrets masked
penenv scan --project <name> [--max-turns N] [--kdbx-password-file F] [-p profile]

# Legacy free-form scans (no project policy applied):
penenv scan https://staging.yourapp.com -p access-control -m deep
penenv scan https://staging.yourapp.com -p auth-session -m standard \
  --instruction "Test credentials: tester@yourapp.com:<see vault>"
penenv scan https://staging.yourapp.com -p api-security \
  --workspace-file ./openapi.yaml
penenv ingest                   # usually auto; also: dashboard "Re-ingest"

# Formatted pen-test report (cover, contents, executive summary, findings by
# severity and by type, with code PoCs and proposed corrections):
penenv report --project <name>                      # latest scan -> HTML + PDF + Word
penenv report --run <run_id> --formats html,pdf     # a specific run, chosen formats
# or from the dashboard: New scan / Scans & history / a run card -> "Generate pen-test report".

# Host-side CVE knowledge feed (never runs in the sandbox); see docs/cve-feed.md:
penenv cve sync                 # refresh the local NVD/OSV/GHSA/KEV/Exploit-DB library
penenv cve status               # size + per-source freshness
penenv cve match --term "openssh 8.1"
```

Scan profiles map 1:1 to OWASP Top-10 SaaS classes; `-m quick|standard|deep`
controls Strix's agentic depth. Full reports stay in `strix_runs/<run>/`
(penetration_test_report.md, per-finding markdown, SARIF in `sarif/sarif.json`).
Generated client-ready reports are written to `reports/`; see `docs/reporting.md`.

## Tracker lifecycle

`ingest.py` keys findings by (target, endpoint, method, finding-type bucket),
not by run, so:

- a finding present in run N and absent in run N+1 → status **fixed**
- a fixed finding that reappears → **reopened** (open)
- manual `accepted` / `false_positive` statuses survive re-detection

The dashboard shows open counts by severity, findings-per-run trend, full
evidence per finding (description, impact, PoC, technical analysis), links to
raw Strix reports, and per-finding status control.

## Project controls and enforcement

A Project page holds the engagement: business/system context, typed scope lists,
keysafe logins, hat level, aggression level (L0–L5) and per-tool switches.
`penenv scan --project` turns it into a per-scan policy (`tracker/policy.py`).
Full tables: `docs/enforcement-matrix.md`. Evidence per task: `docs/acceptance-evidence.md`.

| Control | What it does | Enforced by | Proof |
|---|---|---|---|
| Typed scope (IP / Hostname / URL / CIDR) | Data must match its type; duplicates blocked within and across In/Out lists; CIDR overlap is a warning | Server at save time (client mirrors it) | `tests/test_scope.py`, `tests/test_api.py` |
| Out-of-scope list | Dropped at a per-scan nftables egress gateway; sandbox sits on an internal network with no other route | HARD-net, every hat level | `docs/t05-egress-demo.log`; smoke scans: decoy host received 0 packets |
| Hat level (knowledge) | White: all credentials + white-box source analysis; Grey: credentials, each tied to an in-scope login URL, no white-box; Black: no credentials, no white-box | Save-time rejection; credential tools never registered for Black | `tests/test_scope.py`, `tests/test_policy.py` |
| Test position (independent of hat) | External: in-scope must be internet-facing; Internal: in-scope must be internal (private IPs/ranges, internal names, URLs on private hosts); External + Internal: either. Migration default: White → both, Grey/Black → external | Save-time rejection + rechecked at scan time (DNS) | `tests/test_scope.py::TestPosition`, `tests/test_policy.py`, `tests/test_api.py` |
| Aggression L0–L5 | Sets Strix scan mode, turn cap, connection/bandwidth caps, allowed binaries and method rules | HARD-net (rate), HARD-binary, HARD-config, SOFT-method | `tests/test_policy.py`, `docs/t43-rate-demo.log` |
| Per-tool switches (auto/on/off) | Override the level. Disabled binaries are replaced by a read-only deny stub; disabled Strix tools are removed from the agent | HARD-binary / HARD-tool; brute force, DoS, destructive = SOFT-method; SE, physical, CVSS, retest = CONTRACT | `docs/t52-stub-demo.log`, `tests/test_policy.py` |
| CVE knowledge feed (host-side) | Local NVD/OSV/GHSA/CISA-KEV/Exploit-DB library, refreshed by `penenv cve sync`; the project's `stack` is matched and the relevant CVEs are injected into the agent's instructions as text. Sandbox network unchanged (fail-closed) — host never lets the sandbox fetch CVE data | Host only; `tracker/cvefeed.py` | `tests/test_cvefeed.py`; `docs/cve-feed.md` |
| Research mode (`research` switch) | Hypothesis-driven vulnerability chaining and unknown-flaw discovery (`profiles/research.md`); still bound by scope/rate/method. Refused unless authorised: lab/internal needs a self-authorisation, external/destructive needs an active, unexpired authorisation record (dashboard → Authorisations) covering every target | SOFT-method + fail-closed gate in `build_policy` (`tracker/authorisation.py`) | `tests/test_authorisation.py`; `docs/research-mode.md` |
| Keysafe | Individual fields per login; password/API key masked on read; reveal is audited | Tracker DB, localhost only | `tests/test_api.py` |
| MFA (KeePassXC) | KeePassXC is only the authenticator: register a setup key, recover one-time codes. Seeds never enter the tracker DB; master password never on argv or disk | `keepassxc-cli` via stdin | `tests/test_authenticator.py`, `tests/test_totp.py` (RFC 6238 vectors) |
| Scan-time credential channel | The agent fetches logins/OTP codes by label through `get_test_credential` / `get_mfa_code` with a per-scan token; every fetch audited; token dies when the scan ends | Tracker API | `tests/test_scan_channel.py`; MFA demo scan 7f692801 |
| Violation audit | Denied invocations and gateway drop counters go to `scan_audit/<scan>/` and the project's run view | Tracker | `tests/test_scan_channel.py`; scan c579d3af |

Precedence: **switch > aggression > hat > profile defaults**, except three invariants
nothing overrides: out-of-scope is always dropped, Black hat never has credentials,
DoS/destructive need a written authorisation reference.

Honest limits: HARD-binary stops a *binary*, not a *method* — the agent could
re-implement brute force in Python. That residual risk is bounded by the gateway's
scope and rate caps and is listed as SOFT in the matrix. Grey/Black projects cannot
target the local demo app (it is internal by definition), so Grey/Black scan
behaviour is proven by policy tests rather than a live scan.

## Safety rules

- Scan only systems you own or are authorized to test. Demo containers bind to
  127.0.0.1 only.
- Strix runs inside its own sandbox container. With `--project`, credentials
  are fetched by label through the audited channel and never written into the
  instruction file; never put passwords in `--instruction` text.
- `scan_audit/` holds per-scan policy, denials and counters (0700) — confidential.
- Reports may contain live exploit evidence — treat `strix_runs/` as
  confidential.
- The tracker listens on 127.0.0.1:8766 and is intentionally not exposed.

## Limits & next steps

- Per-role test accounts come from the Project keysafe. White-box mode is used
  only when a source path is set on the project. No CI gate yet (Strix supports
  `--fail-on SEVERITY` for pipelines).
- Keysafe passwords are plaintext at rest in `tracker/penenv.db` (file
  permissions + localhost binding only); MFA seeds live in the encrypted
  KeePassXC database.
- Finding identity is heuristic; review merged rows in the dashboard and split
  via future note/split support if a bucket is too coarse.
