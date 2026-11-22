# Project Controls — Implementation Plan (5 points)

> **SUPERSEDED (2026-11-22).** This was the first draft. The as-built design and its
> proofs are in `docs/enforcement-matrix.md` (source of truth, test-checked against
> `tracker/policy.py`) and `docs/acceptance-evidence.md`. Claims below that turned out
> to be wrong, and what replaced them:
> 1. *Caido proxy denylist = [HARD] out-of-scope block* — **wrong**: Caido scopes only
>    filter what proxy tools see, and the agent can edit them. Replaced by a per-scan
>    nftables egress gateway (HARD-net, `docs/t05-egress-demo.log`).
> 2. *PATH-priority exec wrapper* — **wrong**: bypassable by absolute path / `bash -c`.
>    Replaced by read-only deny stubs bind-mounted over binaries (HARD-binary,
>    `docs/t52-stub-demo.log`) and removal of Strix function tools (HARD-tool).
> 3. *L0 = HTTP GETs + `whatweb`* — **wrong**: that touches the target. L0 now means
>    zero target packets (empty gateway allowlist).
> 4. *`hydra`, `gobuster`, `whatweb`, DoS tools* — **not in the sandbox image**
>    (`docs/sandbox-inventory.md`); brute force and DoS are SOFT-method switches.
> 5. *`totp_seed` in the keysafe* — replaced per decision Q2: seeds live only in the
>    KeePassXC authenticator database, never in the tracker DB.

Working spec for the penenv Project page controls. Grounded in verified facts:
Strix agent 1.7.0 (uv tools venv), `strix-sandbox` container (Kali-class tools via
`exec_command`), Caido proxy scope allow/deny lists (`scope_rules` tool), `keepassxc-cli`
on host, tracker (`tracker/server.py` stdlib HTTP + SQLite `penenv.db`, `tracker/static/index.html`).

Enforcement honesty labels used throughout:
- **[HARD]** = technically enforced; agent cannot bypass at runtime.
- **[SOFT]** = instruction-level (system-preamble); followed by the LLM, not technically guaranteed.

---

## Phase 0 — Verification spikes (before any wiring)

| # | Spike | Why |
|---|-------|-----|
| 0.1 | Dump full tool inventory of `strix-sandbox` image (`ls /usr/bin /usr/local/bin`, check PATH order) | Point 4 matrix must name real tools; point 5 wrapper depends on PATH precedence |
| 0.2 | Inspect `strix/config/models.py` schema + what `--config` accepts | Determine if config can restrict tools natively (cheaper than wrapper) |
| 0.3 | Confirm `keepassxc-cli` TOTP support (`show --totp` / TOTP Seed attribute) | Point 2 KeePass MFA path |
| 0.4 | Confirm RFC 1918/CGNAT helper edge cases (100.64/10, IPv6 ULA) | Point 3 internet-facing rule |

---

## Point 1 — Typed endpoint scope lists (Type + Data, validated, deduped)

**Goal:** In/Out-of-scope entries become `{type, data}` objects; data must match type; duplicates blocked within and across lists; changing type clears data.

### Changes
- **`tracker/server.py`**
  - Schema migration: `endpoints_in` / `endpoints_out` string lists → object lists. On read, infer type for legacy strings (valid IPv4/6 → `ip`; valid CIDR → `cidr`; `http(s)://…` → `url`; else `hostname`).
  - `validate_endpoint(type, data)`:
    - `ip` → `ipaddress.ip_address()` (v4+v6)
    - `cidr` → `ipaddress.ip_network(strict=False)` (v4+v6)
    - `hostname` → RFC-1123 regex, labels 1–63, total ≤253
    - `url` → `urllib.parse`: scheme ∈ {http, https} + non-empty host (hostname or IP)
  - Duplicate rule on save: normalize (`lowercase`, strip scheme, strip trailing `/`, canonicalize IP); reject exact-normalized dup **within** a list (400, names the entry) and **across** lists (400, names both lists).
- **`tracker/static/index.html`**
  - Each scope row: `[type ▼][data][✕]`. Types: IP Address / Hostname / URL / CIDR.
  - Changing a row's type **clears its data field** (requirement), and client-side validation mirrors server rules pre-submit; violations shown as inline row errors, not silent drops.

### Verification
- PUT with bad CIDR / bad IP / `banana` → 400 with reason.
- Dup in-list → 400; same host in-scope and out-of-scope → 400.
- Legacy project with string endpoints loads and migrates on first read.

---

## Point 2 — Keysafe individual fields + KeePassXC/MFA

**Goal:** Per-entry fields stay individual (label / username / secret / notes), add TOTP seed with live code generation, and sync entries to/from a KeePassXC `.kdbx`.

### Changes
- **Schema/fields:** add `totp_seed` to keysafe entries. Masked like `secret` (`********` on every read), reveal audited (same `key_access_audit` path).
- **MFA "registered and used":** "Copy MFA code" button → server computes RFC 6238 from the stored seed (stdlib `hmac`, 30 s step, 6 digits, SHA1 default) and returns the current code; **each code generation is audited** (it is credential material). Seed stored so KeePassXC's own TOTP also works (mapped to KeePassXC `TOTP Seed` custom attribute on export).
- **KeePassXC sync (`keepassxc-cli`, present on host):**
  - "Sync → KeePass": writes keysafe entries into group `penenv/<project>` of a chosen `.kdbx`; "Sync ← KeePass": imports that group back.
  - Master password supplied **per operation** in the request body (localhost only), passed to `keepassxc-cli` via environment variable, **never persisted or logged**; operation itself audited (counts + labels, no secret material).
  - If `keepassxc-cli` missing → endpoint returns a clear not-available error (no silent fake).

### Verification
- RFC 6238 test vector check for the TOTP generator.
- Export → wipe keysafe → import → masked-compare equality.
- Audit rows written for reveal and for each MFA code fetch; `ps` during sync shows no password on the command line (env-var check).

---

## Point 3 — White / Grey / Black hat gating

**Goal:** Hat level actively restricts what a project may contain; out-of-scope always observed at every level.

### Semantics (save-time enforcement, [HARD] on project content)

| Level | In-scope allowed | Keysafe |
|---|---|---|
| White | Everything entered | Full access |
| Grey | Internet-facing only: URLs (any host), IPs/CIDRs not private/loopback/link-local/CGNAT (100.64/10); hostnames accepted but flagged "resolve at scan time" | Allowed ("associated credentials") |
| Black | Same internet-facing rule as Grey | **Rejected entirely** — save with credentials → 400 |

- Out-of-scope list: preserved and **displayed under all three levels** (banner in the Project editor); at scan time (Point 4/5 wiring) it becomes the proxy denylist — ~~[HARD]~~ *(superseded: see banner item 1 — enforced by the egress gateway instead)*.

### Changes
- `tracker/server.py`: `is_internet_facing(entry)` helper (Phase 0.4 edge cases); POST/PUT enforce per level with explicit 400 messages ("Black-hat projects may not carry credentials", "Grey-hat in-scope entry 10.0.0.5 is not internet-facing").
- `index.html`: on hat change, re-validate; Black dims + disables keysafe section with explanation; Grey flags non-internet-facing rows; out-of-scope banner always visible.

### Verification
- Save Grey project with `192.168.1.0/24` in-scope → 400. Black with one key → 400. White unrestricted. Banner present in all levels.

---

## Point 4 — Aggressiveness → tools/methods matrix  ⛔ *approval gate: proposal only now*

**Goal:** Six levels map to real harness mechanisms. This table is the deliverable for approval **before** implementing.

| Level | Strix mode | Tools/methods allowed | Blocked | Enforcement |
|---|---|---|---|---|
| L0 Passive recon | `quick` + recon-only profile | HTTP GETs via proxy, `whatweb`, passive search (`search_web`), DNS | port scans, cred attempts, active exploitation | [SOFT] preamble + [HARD] proxy scope |
| L1 Safe active | `quick` | + `nmap` non-intrusive (`-sT/-sV`, no `-A`), safe nuclei templates (non-destructive tags), banner grabs | brute force, sqlmap, exploit attempts | [SOFT] + exec wrapper [HARD]* |
| L2 Standard (default) | `standard` | Full OWASP profile suite; authenticated flows via keysafe; `sqlmap` bounded (risk≤1/level≤2); `ffuf` small wordlists; manual proxy replay | DoS, destructive payloads, credential dumping | [SOFT] + wrapper [HARD]* |
| L3 Aggressive | `standard`/`deep` | + larger wordlists, `sqlmap` risk≤3/level≤3, heavier fuzz parallelism, exploit PoC chains on confirmed vulns | DoS, irreversible data changes | [SOFT] + wrapper [HARD]* |
| L4 Very aggressive | `deep` | + `hydra`/brute force, auto-exploitation of confirmed findings, high-rate fuzzing | DoS, data destruction | [SOFT] + wrapper [HARD]* |
| L5 Destructive-capable | `deep` | + load/DoS tests, data-altering payloads — requires explicit destructive switch + written authorization field | — | [SOFT] + wrapper [HARD]* + mandatory legal ack |

*(Superseded — this table and the switch table below are replaced by `docs/enforcement-matrix.md`; see banner items 2–4.)*

\* Wrapper honesty: the exec wrapper [HARD]* enforces tool-name/pattern policy via a mounted policy file; see Point 5. It is strong PATH-level control, not a sandbox rewrite — documented residual risk: exotic invocations by absolute path outside PATH order; mitigated by instruction + audit, stated openly.

**Wiring tasks (after approval):** `penenv scan --project <name>` builds: proxy scope from endpoints (Point 1), credentials from keysafe (masked in logs), mode from table, policy file from switches (Point 5), instruction preamble combining hat level + aggression + profile.

---

## Point 5 — Per-tool/method switches (override everything)  ⛔ *approval gate: proposal only now*

**Goal:** A "Tool & Method Permissions" grid where each switch is authoritative: **switch > aggression level > hat level > profile defaults**.

### Switch set (each maps to a real mechanism)

| Switch | Default | Enforcement |
|---|---|---|
| Port scanning (`nmap` family) | follow aggression | wrapper [HARD]* |
| Web fuzzing / dir bust (`ffuf`, `gobuster`) | follow aggression | wrapper [HARD]* |
| SQL injection automation (`sqlmap`) | follow aggression | wrapper [HARD]* |
| Vulnerability templates (`nuclei`) | on | wrapper [HARD]* |
| Credential brute force (`hydra` family) | follow aggression | wrapper [HARD]* |
| Proxy request replay (`curl`/proxy client) | on | [SOFT] (intrinsic tool) |
| Browser automation (`agent-browser`) | on | [SOFT] + wrapper |
| DoS / load generation | off | wrapper [HARD]* |
| Destructive / data-altering payloads | off | [SOFT] + wrapper patterns [HARD]* |
| Auto-exploit confirmed findings | follow aggression | [SOFT] |
| Social engineering | off | [SOFT] (declare-only; not executable in sandbox) |
| Physical attack vectors | off | [SOFT] (declare-only, contract record) |

### Design
- **Policy file:** server generates `/workspace/.penenv-policy.json` per scan from switches + aggression ceiling; injected via `--workspace-file`.
- **Exec wrapper:** small shell shim placed ahead in sandbox PATH (Phase 0.1 verifies precedence) that checks the invoked tool name against policy; deny → prints policy violation, returns non-zero. Every violation appended to an audit log surfaced in the tracker run view.
- **Conflict warnings (UI):** L0 + brute-force switch ON → toast warning "switch overrides aggression ceiling"; L5 + destructive OFF → info "L5 destructive methods disabled by switch".
- **Precedence doc + UI footnote:** the one-line rule above, shown in the grid header.

### Verification
- Scan smoke on demo app: L1 project with hydra switched on → wrapper denies hydra invocation, violation in audit log, scan continues; out-of-scope host fetch blocked at proxy (Caido scope confirms).
- Unit: policy generator output for every aggression×switch combination sample set.

---

## Delivery order & verification strategy

1. **P1** Point 1 (schema + validation + UI) → curl tests
2. **P2** Point 2 (TOTP + KeePass sync) → vector + roundtrip tests
3. **P3** Point 3 (hat gating) → per-level save tests
4. **Gate:** present Points 4–5 matrix approval (this document, sections 4–5)
5. **P4** Phase 0 spikes → policy generator → `--project` scan mode → wrapper install → smoke scans (L1 and L4) with audit review
6. Each phase: restart tracker (`fuser -k 8766/tcp`), dashboard HTTP 200, then functional curl checks before declaring done.
