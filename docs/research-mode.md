# Research mode

Research mode lets the agent work like a human security researcher: form explicit
hypotheses, chain individually-minor weaknesses into higher-impact attacks, and probe
for **previously-unknown** flaws (logic/business-flaw abuse, state-machine and
trust-boundary attacks, parser differentials) instead of only running catalogued checks.

It is a `SOFT-method` switch (`research`) that adds `profiles/research.md` to the rules of
engagement. It widens *how creatively the agent reasons* — never *what it may touch*. The
HARD-net scope, rate caps and HARD-binary tool limits from the project's level still bind
every action, and the agent is told to prove each step and stop at proof.

## Authorisation gate (fail-closed)

Because research is powerful, it is refused unless the engagement is authorised. The gate
lives in `tracker/authorisation.py` and is enforced in `policy.build_policy`:

| Engagement | What is required |
|---|---|
| Lab / internal only, non-destructive (every in-scope target internal; no destructive/DoS) | A **self-authorisation**: any non-empty value in the project's `authorisation` field. |
| **External** targets, or research combined with **destructive/DoS** | A **structured authorisation record** (dashboard → **Authorisations** tab) that is active (not revoked), unexpired, sets `research_allowed: true` (and `destructive_allowed: true` if destructive/DoS is used), and whose `scope` covers every in-scope target. A free-text reference alone is refused. |

If the gate refuses, research mode is forced **off** and the reason is reported as a plan
error — the scan either runs without research or is corrected first. Nothing is silently
downgraded.

## The authorisation record

Records live in the tracker database (`authorisations` table, git-ignored with the rest of
`*.db`, so real client contracts never enter the repository). Fill them in on the
dashboard's **Authorisations** tab, then set the project's authorisation reference (Project →
Settings → *Rules of engagement*) to the record's reference — the field suggests active
records and says whether the value is linked to a record or is only a free-text
self-authorisation. Fields:

- `ref` — the reference projects link to (letters, digits, `. _ / -`).
- `client`, `contract_ref`, `authorised_by` — provenance of the sign-off. Client and
  signatory are always required; the contract/SOW reference **and** an expiry date are
  required whenever research or destructive testing is permitted.
- `expires` — `YYYY-MM-DD`; a past or unparseable date is treated as expired.
- `research_allowed`, `destructive_allowed` — explicit permissions (default off).
- `scope` — one URL, hostname, IP or CIDR per line; every in-scope target must be covered
  (an IP inside a scope CIDR counts as covered).
- `notes` — window, emergency contact, exclusions.

Records are never deleted. **Revoke** a record when a contract ends or is withdrawn: any
project that names it is then refused research mode outright, even for lab work. Every
create, update and revoke is written to `authorisation_audit` and shown under the form.
A revoked record cannot be edited — create a new one.

The same operations are available over the local API (`GET/POST /api/authorisations`,
`GET/POST /api/authorisations/<id>`, `POST /api/authorisations/<id>/revoke`).

## Running it

Enable the `research` switch on the project (and set `authorisation`), then:

```bash
penenv scan --project NAME --dry-run     # shows "research mode: ON (authorisation: <ref>)"
                                         # or the refusal reason, plus the full rules of engagement
penenv scan --project NAME
```

The plan summary (research flag + authorisation reference) and the exact rules of
engagement given to the agent are written into the per-scan `scan_audit/<id>/` trail.
