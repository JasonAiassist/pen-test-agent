# Enforcement matrix — aggression levels (T4.1) and per-tool switches (T5.1)

Approved in principle by you (Q3/Q4 = yes, "redrafted from the real sandbox inventory").
Every tool named here exists in `sandbox-inventory.md` or in Strix's `_BASE_TOOLS`
(`strix/agents/factory.py:568`). The machine-readable source of truth is `tracker/policy.py`;
`tests/test_policy.py` checks that this document and the code agree.

## Enforcement classes

| Class | Mechanism | Can the agent get round it? |
|---|---|---|
| **HARD-net** | Per-scan egress gateway (`docker/egress-gw`, nftables in its own netns). Allowlist = in-scope IPs/CIDRs:ports; out-of-scope = explicit drop; rate caps. Sandbox on an `--internal` network with no host IP | No. Proven in `docs/t05-egress-demo.log`, including as root |
| **HARD-binary** | Deny stub bind-mounted read-only over the binary **and** its package directory | Not that binary (no `CAP_SYS_ADMIN`, so no unmount). The *method* can still be re-written in Python/Go |
| **HARD-tool** | The Strix function tool is removed from the agent's tool list by `bin/penenv-launch.py` | No, the tool does not exist for the agent |
| **HARD-config** | Strix flags/env set by penenv (`--scan-mode`, `--max-turns`, `STRIX_TELEMETRY=0`, no search API keys) | No |
| **SOFT-method** | Rules-of-engagement preamble given to the agent | Yes in principle. Bounded by HARD-net (scope + rate) and recorded in the audit |
| **CONTRACT** | Recorded on the project and in the report only. Nothing executable exists | n/a |

## Precedence

**switch > aggression level > hat level > profile defaults**, with three invariants that nothing overrides:
1. Out-of-scope entries are always dropped at the gateway (HARD-net).
2. Black hat carries no credentials (save-time rejection), so credential/MFA tools are never registered.
3. `DoS` and `Destructive` need the written authorisation reference field filled in, at any level.
4. `research` mode is refused unless the project carries an authorisation reference. Lab/internal,
   non-destructive research accepts a lightweight self-authorisation (any non-empty reference); but
   research against **external** targets, or combined with **destructive/DoS**, requires a *structured*
   authorisation record (`authorisations/<ref>.json`) that is unexpired, permits research (and
   destructive, if used), and whose scope covers every in-scope target. Enforced fail-closed in
   `build_policy` via `tracker/authorisation.py`. See `docs/research-mode.md`.

## Hat level vs test position (config v4)

These are two independent settings, as in CREST/CHECK scoping:

| Setting | Values | What it controls |
|---|---|---|
| Hat (knowledge) | White / Grey / Black | Credentials (Black: none; Grey: each tied to an in-scope login URL) and Strix white-box mode (White only, when a source path is set) |
| Test position | External / Internal / External + Internal | Which in-scope endpoints are acceptable: External = internet-facing only, Internal = internal only, both = either. Checked at save time and re-checked at scan time (DNS) |

The out-of-scope list is enforced at the gateway under every combination. Pre-v4 projects
migrate to White → both, Grey/Black → external, so their behaviour is unchanged.

A switch is tri-state: **auto** (follow the level) · **on** · **off**. "On" can open what the level closed
(with a warning in the UI); "off" always closes.

## Aggression levels

| | L0 Passive | L1 Non-intrusive | L2 Standard | L3 Aggressive | L4 Very aggressive | L5 Destructive |
|---|---|---|---|---|---|---|
| Target packets | **none** (gateway allowlist empty) | in-scope only | in-scope | in-scope | in-scope | in-scope |
| Strix `--scan-mode` | quick | quick | standard | standard | deep | deep |
| `--max-turns` per agent | 40 | 120 | 300 | 500 | 500 | 500 |
| New connections / s (HARD-net) | 0 | 5 | 20 | 50 | 150 | 500 |
| Bandwidth cap (HARD-net) | 0 | 256 KB/s | 1 MB/s | 4 MB/s | 10 MB/s | none |
| Sub-agents | off | on | on | on | on | on |
| Binaries allowed (auto) | none | curl, wget, httpx, wafw00f, katana, agent-browser/chromium, nmap | L1 + ffuf, dirsearch, arjun, nuclei, sqlmap, jwt_tool, nc/ncat | L2 + naabu | L3 | L3 |
| Method rules (SOFT) | OSINT only | no fuzzing, no injection payloads, nmap `-sT`/`-sV` top-100 only | sqlmap `--risk 1 --level ≤2`; nuclei without `dos,intrusive` tags; small wordlists | sqlmap risk ≤2 level ≤3; nuclei without `dos`; PoC exploit chains | sqlmap risk 3; brute force allowed; auto-exploit | DoS and data-altering payloads (if switched on + authorised) |
| Defaults for method switches | all off | all off | auto-exploit off | auto-exploit on | brute force + auto-exploit on | + DoS, destructive on (still need authorisation) |

Not in the sandbox (so not switchable as binaries): `hydra`, `medusa`, `john`, `hashcat`, `gobuster`, `nikto`,
`whatweb`, `msfconsole`, every DoS/load tool. Brute force and DoS are therefore **method** switches.

## Switches

| Switch id | Covers | Class | Default (auto) |
|---|---|---|---|
| `nmap` | `/usr/bin/nmap`, `/usr/lib/nmap` | HARD-binary | L1+ |
| `naabu` | `/usr/bin/naabu` | HARD-binary | L3+ |
| `httpx` | `/home/pentester/go/bin/httpx` | HARD-binary | L1+ |
| `katana` | `/home/pentester/go/bin/katana` | HARD-binary | L1+ |
| `wafw00f` | `~/.local/bin/wafw00f` + pipx venv | HARD-binary | L1+ |
| `ffuf` | `/usr/bin/ffuf` | HARD-binary | L2+ |
| `dirsearch` | `~/.local/bin/dirsearch` + pipx venv | HARD-binary | L2+ |
| `arjun` | `~/.local/bin/arjun` + pipx venv | HARD-binary | L2+ |
| `nuclei` | `/usr/bin/nuclei`, `~/.local/nuclei-templates` | HARD-binary | L2+ |
| `sqlmap` | `/usr/bin/sqlmap`, `/usr/share/sqlmap` | HARD-binary | L2+ |
| `jwt_tool` | `~/.local/bin/jwt_tool` | HARD-binary | L2+ |
| `netcat` | `nc`, `netcat`, `nc.traditional`, `ncat` | HARD-binary | L2+ |
| `browser` | `agent-browser` (+ node module), `chromium` (+ `/usr/lib/chromium`) | HARD-binary | L1+ |
| `curl_wget` | `curl`, `wget` | HARD-binary | L1+ |
| `oob_callbacks` | `interactsh-client` **and** opens the public interactsh servers at the gateway (data leaves for a third party) | HARD-binary + HARD-net | off |
| `subdomain_enum` | `subfinder` (needs public data sources; these are opened at the gateway only if on) | HARD-binary + HARD-net | off |
| `code_scanners` | `trufflehog`, `gitleaks`, `bandit` (local analysis, White hat with source) | HARD-binary | on when a source path is set |
| `web_search` | Strix `web_search`, `web_get_contents` (queries go to Perplexity/Exa) | HARD-tool | off |
| `subagents` | `create_agent`, `send_message_to_agent`, `wait_for_agents`, `stop_agent`, `view_agent_graph` | HARD-tool | L1+ |
| `mcp` | `list_mcps`, `search_mcp_tools`, `get_mcp_tool_schema`, `describe_mcp`, `call_mcp` | HARD-tool | off |
| `request_replay` | `repeat_request` (Caido replay) | HARD-tool | L1+ |
| `telemetry` | `STRIX_TELEMETRY` (PostHog/Scarf) | HARD-config | off |
| `use_credentials` | registers `get_test_credential` (keysafe, audited, per-scan token) | HARD-tool | on unless Black hat |
| `use_mfa` | registers `get_mfa_code` (KeePassXC authenticator, audited, per-scan token) | HARD-tool | on unless Black hat |
| `bruteforce` | password guessing / credential stuffing | SOFT-method (rate-bounded by HARD-net) | L4+ |
| `dos` | load / resource exhaustion (lifts the rate cap to L5's) | SOFT-method + HARD-net | L5, needs authorisation |
| `destructive` | data-altering / deleting payloads | SOFT-method | L5, needs authorisation |
| `autoexploit` | exploit confirmed findings beyond proof | SOFT-method | L3+ |
| `research` | security research mode — hypothesis-driven vulnerability chaining and unknown-flaw discovery (adds `profiles/research.md`) | SOFT-method | off; needs authorisation (see below) |
| `social_engineering` | phishing, pretexting | CONTRACT (nothing executable) | off |
| `physical` | on-site testing | CONTRACT | off |
| `notify_critical`, `free_retest`, `cvss` | reporting/contract terms | CONTRACT | off |

What cannot be switched off: `exec_command` (the shell) and the HTTP proxy are the agent's core. Their reach
is what HARD-net and HARD-binary bound.
