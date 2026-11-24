# penenv help sheet

A quick guide to the penenv dashboard: what each tab is for, and a checklist for running a test.

**Open the dashboard:** `bin/penenv tracker start`, then go to <http://127.0.0.1:8766>
(`bin/penenv tracker url` prints the address, `bin/penenv tracker restart` restarts it).

> Only test systems you own, or systems you have **written permission** to test.
> penenv enforces scope, but you're still responsible for what you point it at.

---

## Pre-flight checklist (do this once per engagement)

- [ ] **Agent config:** a provider is set up and **Use this model** has been pressed. The banner shows the model scans will use.
- [ ] **Authorisations:** if the client signed an authorisation, record it here (reference, client, signatory, expiry, scope, permits).
- [ ] **Project → 1 Overview:** project name, business context, system under test.
- [ ] **Project → 2 Test settings:** hat level, test position, aggressiveness, testing window, rules of engagement, authorisation reference.
- [ ] **Project → 3 Scope:** every in-scope endpoint is listed, and anything off-limits is under **Out of scope**.
- [ ] **Project → 4 Credentials:** test-account logins are added (not needed for Black hat).
- [ ] **Project → 5 Tool switches:** check any red or yellow warnings and set overrides.
- [ ] **Project → At a glance:** shows **problems: none**. Then press **Save project**.
- [ ] **New scan:** pick the project and press **Dry-run check**. Read the plan.
- [ ] **New scan:** set a **Max budget (USD)** if you want a spending cap, then press **▶ Start scan**.

## After each scan

- [ ] Watch **Scan progress** until the run finishes (press **■ Stop** to abort).
- [ ] **Dashboard:** review new findings. Click a row to see its evidence and the per-finding report.
- [ ] Triage each finding: mark it **fixed**, **accepted** (known risk) or **false_positive**, or leave it **open**.
- [ ] Generate the client report (from a run card or **Scans & history**, or `bin/penenv report --project NAME`).
- [ ] After the client fixes things, re-scan and compare in **Project → 6 Scans & history**.

---

## The tabs

### Top bar
- **Meta line:** when runs were last ingested, and how many targets are known.
- **Re-ingest runs:** reloads every scan in `strix_runs/` into the database. It's safe to repeat, because findings aren't duplicated. Use it if a finished scan isn't showing up.

### 1. Dashboard: results across all scans
| Section | What it's for |
|---|---|
| Summary cards | Open findings in total and by severity (CRITICAL → INFO), plus the number fixed. |
| Findings per run | A bar chart that shows whether each new scan found more or fewer issues. |
| Scan runs | Every ingested run, with its target, date and findings. Open its Strix report from here. |
| Findings | The main list. Filter chips: **Active** (open and reopened), **All**, **Fixed**, **Accepted**, **False positive**. The search box looks in title, endpoint and evidence. Click a row for evidence. Use **Set status** to triage. |

**How a finding's status changes:**
- **open:** found by a scan.
- **fixed:** set automatically when a later scan of the same target no longer finds it, or set by you.
- **reopened:** a "fixed" finding was found again.
- **accepted** / **false_positive:** your manual decision. Later scans keep these statuses, and you can change them back at any time.

### 2. Project: the rulebook for one engagement
A project is the policy a scan must follow. Work through the sub-tabs from left to right, then press **Save project**.
Use **＋ new project**, **Open another project…** and **Delete** to manage projects.

| Sub-tab | What you set |
|---|---|
| **1 · Overview** | Name, business context and system under test, all of which give the agent context. **At a glance** summarises the project and lists any problems. Click a card to jump to its sub-tab. |
| **2 · Test settings** | **Hat:** Black (no knowledge, no logins), Grey (partial) or White (full knowledge, plus an optional source-code path for white-box analysis). **Position:** external, internal, or both. **Aggressiveness:** L0 passive up to L5 destructive (L5 isn't recommended). Also the testing window, rules of engagement, and the **authorisation reference**. |
| **3 · Scope** | **Endpoints in scope:** the only targets the agent may reach. **Out of scope:** blocked at the scan firewall at every level, with no exceptions. |
| **4 · Credentials** | The keysafe for test-account logins. Passwords and keys are stored server-side and shown masked. Saving keeps the stored value unless you type a new one. MFA seeds stay in KeePassXC and never go into this database. |
| **5 · Tool switches** | Turns individual tools and methods on or off: nmap, ffuf, sqlmap, nuclei, the browser, brute force, DoS, destructive payloads, research mode, and others. **auto** follows the aggressiveness and hat level, while **on**/**off** overrides them. Order of priority: *switch > aggression level > hat level > profile defaults*. Three things can't be overridden: out-of-scope blocking, the Black hat no-credentials rule, and the authorisation requirement. |
| **6 · Scans & history** | Policy-enforced scans run for this project, plus a before/after history of findings on its in-scope endpoints. Use it to show a client what got fixed. |

### 3. New scan: run the agent
- **Project:** pick a saved project. The scan uses exactly that project's settings.
- **Dry-run check:** checks the policy and shows the plan (model, scope, switches) **without touching the target**. Always run this first.
- **▶ Start scan** / **■ Stop:** starts or aborts the scan. **Scan progress** streams the live log.
- **Run options (optional):**
  - **Lower max-turns:** can only shorten the run, never extend it.
  - **Max budget (USD):** a spending cap for model tokens.
  - **Scan profile:** focus the test, e.g. `profiles/injection.md`, `auth-session`, `access-control`, `api-security`, `business-logic`, `data-exposure`, `full-saas` or `research`.
  - **Keep gateway/network:** leaves the sandbox network up after the scan so you can inspect it.
  - **KeePassXC master password:** only needed if a login uses MFA. It's used for this run only and deleted afterwards.
- **Recent scan launches:** click one to re-open its log.

The CLI equivalent is `bin/penenv scan --project NAME [--dry-run] [--max-budget USD]`.

### 4. Authorisations: the paperwork behind risky testing
Records of signed client permission. A project points to one through its **authorisation reference** (Test settings).
- **Needs a record here** (active, not expired, permits the activity, and its scope covers *every* in-scope target): research mode against an **external** target, and any **destructive / DoS** testing.
- **Lab or internal research** only needs a free-text self-authorisation on the project.
- Fields: reference, client, contract/SOW, signatory, expiry, permits (research, destructive/DoS), scope (one URL, host, IP or CIDR per line), notes.
- Records are **never deleted**. Press **Revoke** instead. Every change is recorded in the audit trail shown under the form.

### 5. Agent config: which AI model scans use
- **Model used by scans:** pick a **Provider**, then a **Model** from the dropdown (press **Fetch models** to load the provider's list, or choose **Other…** to type an ID). Set the **Reasoning effort**, then press **Use this model**. The change applies to the **next** scan, and scans already running keep their model.
- **Strix default:** leaves Strix's own `~/.strix/cli-config.json` in charge.
- **Model providers:** add, edit or delete connections (name, type, base URL, API key, API type). **Import from Strix config** copies the model, endpoint and key Strix is already set up with.
- Keys are stored only in `~/.config/penenv/agent.json`, which only you can read. They're never shown again after saving, and never passed to the agent's instructions or the scan sandbox.

---

## Command-line cheat sheet

| Command | Does |
|---|---|
| `bin/penenv up` / `down` | Start or stop the Juice Shop demo target (a safe practice app). |
| `bin/penenv status` | Show containers and services. |
| `bin/penenv demo` | Run a full scan of the local Juice Shop. |
| `bin/penenv scan --project NAME --dry-run` | Validate a project's scan plan. |
| `bin/penenv scan --project NAME` | Run a policy-enforced scan. |
| `bin/penenv ingest` | Same as **Re-ingest runs**. |
| `bin/penenv report --project NAME` | Build the client report (HTML + PDF + Word). |
| `bin/penenv report --run ID --formats html,pdf` | Build a report for one run. |
| `bin/penenv cve sync` / `status` / `match` | Update the local CVE feed and match it against findings (see `docs/cve-feed.md`). |
| `bin/penenv cve key set` | Store an optional NVD API key. |

## Troubleshooting

| Symptom | Try |
|---|---|
| Dashboard doesn't load | `bin/penenv tracker restart` |
| Finished scan not on Dashboard | Press **Re-ingest runs** |
| **Start scan** greyed out | Pick a project, and fix the problems listed in **At a glance** |
| **Fetch models** fails | Check the provider's base URL and API key in **Agent config** |
| Research or DoS refused | Add or renew a matching record in **Authorisations**, and check its scope covers every target |
| Docker permission errors | Your user needs to be in the `docker` group (penenv falls back to `sg docker` automatically) |

More detail: `README.md`, `docs/agent-config.md`, `docs/research-mode.md`, `docs/reporting.md`, `docs/enforcement-matrix.md`.
