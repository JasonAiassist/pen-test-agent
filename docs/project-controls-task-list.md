# Project Controls — Plan Evaluation & Task List

Companion to `project-controls-implementation-plan.md`. Part A is a review of that plan.
Part B lists the tasks, each with a measurable definition of done.

---

## Part A — Plan evaluation

### What holds up
- Splitting the work into phases (tracker-only points 1–3 first, Strix wiring after approval) is sound.
- The validation rules for Point 1 (`ipaddress`, RFC-1123, URL scheme+host) are correct and deterministic.
- Auditing reveals and MFA-code generation is the right call.
- The [HARD]/[SOFT] labelling is useful, but it was applied too generously (see corrections below).

### Corrections (the plan was wrong or overstated)

| # | Plan said | Reality (verified) | Fix |
|---|---|---|---|
| C1 | Out-of-scope is [HARD] via the Caido proxy denylist | The `scope_rules` docstring says scopes *"filter which traffic Caido tools see"*. That is a **view filter, not a block**. The agent can also edit scopes itself, and `nmap`/raw sockets bypass the HTTP proxy completely. | Enforce at the **network layer**: per-scan egress firewall on the sandbox container (iptables/nftables allowlist of resolved in-scope IPs/CIDRs, explicit drop of out-of-scope). Keep Caido scope as a [SOFT] convenience. |
| C2 | A PATH-shim exec wrapper is [HARD]* | Easy to bypass: absolute paths, `bash -c`, `python3` re-implementations, scripts the agent writes itself. | Tool switches use a **per-scan derived sandbox** where disabled binaries are bind-mounted read-only over a deny stub, plus the egress firewall. Label the result honestly as **[HARD-binary]** (that binary can't run) vs **[SOFT-method]** (the method can still be re-implemented in Python, so it's covered by instructions + audit). |
| C3 | L0 "Passive recon" sends HTTP GETs and runs `whatweb` | Both contact the target, so that's active. | L0 = **no target packets**: OSINT, DNS via public resolvers, CT logs, web_search only. Target contact starts at L1. |
| C4 | Grey: "URLs (any host)" are internet-facing | A URL like `http://10.0.0.5/` is internal. | The URL host goes through the same IP check. Hostnames are DNS-resolved at save time **and** at scan time; any private result is rejected or flagged. |
| C5 | MFA "registered and **used**" | The plan only generates codes in the UI. The scanning agent has no way to get a code mid-login. | Add a scan-time TOTP channel: a localhost-bound, per-scan-token endpoint (or MCP tool) the agent calls to get the current code for a named entry, with every call audited. |
| C6 | Point 5 switch list | Written before the tool inventory (Phase 0.1). It also misses Strix's **own function tools**: `web_search` sends queries to Perplexity/Exa (a third party, so client data leaves the machine), plus `spawn agents`, MCP, `apply_patch`, `agent-browser`. | Build the switch list **from** the Phase 0 inventory. Add contract switches for "third-party data egress (web_search)" and "sub-agent spawning". |
| C7 | Point 2 "split keysafe into individual fields" | Already individual inputs (label · username · secret · notes, `index.html:337-371`). | Interpret as: one entry per field, with the **URL/endpoint it's for**, role, and TOTP seed added. **Confirm with you (Q1).** |
| C8 | (not addressed) | The keysafe is plaintext at rest. Credentials passed via the instruction file go to the LLM provider. | Option to make KeePassXC the at-rest store (Q2). Credentials are referenced by label in prompts and resolved via the TOTP/credential channel where possible. The provider exposure is documented. |
| C9 | (not addressed) | No test suite exists (`tests/` absent). Project config is a JSON blob; a migration risks existing data. | Add a `tests/` stdlib-`unittest` suite. Back up `penenv.db` before the migration. Make the migration idempotent. |
| C10 | Hat level only gates scope/creds | Strix has a native `is_whitebox` flag. | White → whitebox prompt + credentials. Grey → blackbox + credentials. Black → blackbox, no credentials. |

### Open decisions (needed before the affected task starts)
- **Q1** (T2.1): What did "split keysafe fields" mean to you, beyond the current four inputs?
- **Q2** (T2.4): Should KeePassXC be the *at-rest store* (keysafe becomes a view onto the .kdbx), or a *sync target* (as planned)? I recommend the at-rest store, because it fixes C8.
- **Q3** (T4.1): Approve the corrected aggression matrix (produced in T4.1).
- **Q4** (T5.1): Approve the final switch list (produced in T5.1 from the real inventory).

---

## Part B — Task list with definitions of done

Status key: ☐ todo · ⛔ blocked on a decision. Every task's DoD includes: the tests pass (`python3 -m unittest discover tests`), the tracker restarts (`fuser -k 8766/tcp`), and the dashboard returns HTTP 200.

### Phase 0 — Foundations & spikes
| ID | Task | Done when |
|---|---|---|
| T0.1 | Create a `tests/` harness (stdlib unittest, temp DB fixture, spins up the server on a random port) | `python3 -m unittest discover tests` runs ≥1 passing test against a throwaway DB; the real `penenv.db` is untouched (mtime unchanged) |
| T0.2 | DB backup + migration framework (`schema_version`, idempotent migrations) | Backup file is created before any migration. Running the migration twice gives an identical DB. A test proves rollback from the backup restores the original projects |
| T0.3 | Sandbox tool inventory | `docs/sandbox-inventory.md` lists every security-relevant binary with its absolute path and version, plus PATH order and language runtimes (python, node, perl, go). Generated by a re-runnable script |
| T0.4 | Strix control-surface spike: `--config` schema, `scan_mode` effects, `is_whitebox`, function-tool list, whether tools can be disabled natively | A short findings doc answers each item with file:line evidence |
| T0.5 | Network-enforcement spike: can penenv start the sandbox with an egress firewall (custom docker network + nftables / `--cap-add NET_ADMIN` init)? | Demo: a sandbox with an allowlist of one IP can reach it, and `curl`/`nmap` to a second IP **fails**. Command and output are recorded |
| T0.6 | `keepassxc-cli` spike: create/add/show/TOTP, password via stdin (not argv) | Scripted round-trip on a temp .kdbx works. `ps` capture shows no password in argv |

### Point 1 — Typed scope lists
| ID | Task | Done when |
|---|---|---|
| T1.1 | Server validator `validate_endpoint(type,data)` for ip/hostname/url/cidr (v4+v6) | Table-driven tests: ≥8 valid and ≥8 invalid cases per type pass (e.g. `256.1.1.1`, `10.0.0.0/33`, `ftp://x`, `-bad-.com`, `banana` all rejected) |
| T1.2 | Normaliser + duplicate detection within and across lists | Tests: duplicate in In → 400; In vs Out duplicate → 400 naming both lists; case/scheme/trailing-slash variants count as duplicates; `10.0.0.1` vs `10.0.0.0/24` returns a **warning** (overlap), not an error |
| T1.3 | Legacy migration (string → `{type,data}`) via T0.2 | Existing projects load with inferred types. Entries that can't be inferred are kept and flagged `invalid` (never silently dropped). Tested |
| T1.4 | UI rows `[type▼][data][✕]`, type change clears data, inline errors, client checks mirror the server | Manual check in browser: change type → field clears. Bad value → red row + message, and save is blocked. Server still rejects if the client check is bypassed (curl test) |

### Point 2 — Keysafe + KeePassXC/MFA  (⛔ T2.1 on Q1, T2.4 on Q2)
| ID | Task | Done when |
|---|---|---|
| T2.1 | Entry schema: label, username, secret, totp_seed, target (link to an in-scope endpoint), role, notes | All fields are individual inputs. Secret and seed are masked on read. Saving masked values preserves them (test) |
| T2.2 | RFC 6238 TOTP generator (SHA1/256/512, 6/8 digits, 30 s) | RFC 6238 Appendix B test vectors all pass |
| T2.3 | "Copy MFA code" UI + endpoint, audited | Click returns the current code. One audit row per fetch, with no seed or code in the row (test) |
| T2.4 | KeePassXC integration (store **or** sync per Q2), password via stdin, never persisted | Round-trip test on a temp .kdbx: export → wipe → import is equal. `ps` shows no password. Grep of DB/logs finds no master password. Clear error if `keepassxc-cli` is missing |
| T2.5 | Scan-time credential/TOTP channel for the agent (C5): per-scan token, localhost, audited | During a demo scan the agent fetches a TOTP code via the channel and completes an MFA login on a test target. The token is rejected after the scan ends |

### Point 3 — Hat-level gating
| ID | Task | Done when |
|---|---|---|
| T3.1 | `is_internet_facing()` covering private, loopback, link-local, CGNAT, multicast, reserved, IPv6 ULA/link-local, URL host, DNS-resolved hostnames | Table tests cover every range plus a URL with a private host and a hostname resolving to a private IP |
| T3.2 | Save-time enforcement: Grey/Black reject non-internet-facing in-scope entries; Black rejects any keysafe entry | Tests: Grey + `192.168.1.0/24` → 400; Black + 1 credential → 400; White accepts both. Switching White→Black on a project with credentials prompts and **does not silently delete** them |
| T3.3 | Out-of-scope always shown and always enforced at scan time (via T0.5 firewall) | Banner visible at all 3 levels (manual). Scan test: out-of-scope IP unreachable from the sandbox under every hat level |
| T3.4 | Map hat → Strix `is_whitebox` / credential injection | Generated scan command/prompt for each level matches the C10 table (unit test on the builder) |

### Point 4 — Aggression matrix  (⛔ Q3)
| ID | Task | Done when |
|---|---|---|
| T4.1 | Rewrite the matrix from the T0.3/T0.4 findings with the C2/C3 corrections; each cell names a real binary/flag and its enforcement class | Doc approved by you (Q3). Every tool named exists in `sandbox-inventory.md` |
| T4.2 | Policy builder: (aggression, hat, switches) → policy JSON (mode, allowed binaries, rate limits, prompt preamble) | Unit tests cover all 6 levels × 3 hats. Precedence switch > aggression > hat > profile is proven by tests |
| T4.3 | Rate limits per level ([HARD] via firewall/tc where feasible) | Measured request rate against a local test target stays under the configured cap at L1 and L2 |
| T4.4 | `penenv scan --project <name>` wiring (targets, scope firewall, creds channel, mode, policy) | A dry-run prints the full resolved plan with secrets masked. A real L1 scan on the demo app completes and findings ingest under the project |

### Point 5 — Per-tool switches  (⛔ Q4)
| ID | Task | Done when |
|---|---|---|
| T5.1 | Final switch list from the inventory, including Strix function tools and data-egress switches (C6) | Approved by you (Q4). Each switch maps to ≥1 concrete binary/tool and an enforcement class |
| T5.2 | Enforcement: deny-stub bind mounts for disabled binaries, Strix function-tool disabling (if T0.4 allows), prompt preamble | Test: switch off `hydra` → `hydra`, `/usr/bin/hydra` and `bash -c hydra` all fail inside the scan sandbox. Disabled function tools are absent from the agent's tool list |
| T5.3 | Violation audit: denied invocations logged and shown in the run view | A forced denied call appears in the tracker run view with timestamp + command (secrets redacted) |
| T5.4 | UI switch grid with precedence footnote + conflict warnings | Manual: L0 + brute-force ON shows the override warning. Saved state round-trips (test) |

### Acceptance (end-to-end)
| ID | Task | Done when |
|---|---|---|
| T6.1 | Two smoke scans (L1 Grey, L4 White) on the demo app with an out-of-scope decoy host | Decoy receives **zero** packets (checked with tcpdump on the decoy). Disabled tools are never executed successfully. Findings ingested. Audit trail is complete |
| T6.2 | Docs: update README + plan with the final enforcement classes | Each claim in the docs has a matching passing test or recorded demo |
