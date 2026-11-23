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
| **External** targets, or research combined with **destructive/DoS** | A **structured authorisation record** `authorisations/<ref>.json` that is unexpired, sets `research_allowed: true` (and `destructive_allowed: true` if destructive/DoS is used), and whose `scope` covers every in-scope target. A free-text reference alone is refused. |

If the gate refuses, research mode is forced **off** and the reason is reported as a plan
error — the scan either runs without research or is corrected first. Nothing is silently
downgraded.

## The authorisation record

Copy `docs/authorisation-example.json` to `authorisations/<ref>.json` (that directory is
git-ignored, so real client contracts never enter the repository) and set the project's
`authorisation` field to `<ref>`. Fields:

- `ref`, `client`, `contract_ref`, `authorised_by` — provenance of the sign-off.
- `expires` — `YYYY-MM-DD`; a past or unparseable date is treated as expired.
- `research_allowed`, `destructive_allowed` — explicit permissions (default `false`).
- `scope` — endpoint values (`"https://app.example.com"`) or `{type,data}` entries,
  including CIDRs; every in-scope target must be covered.

## Running it

Enable the `research` switch on the project (and set `authorisation`), then:

```bash
penenv scan --project NAME --dry-run     # shows "research mode: ON (authorisation: <ref>)"
                                         # or the refusal reason, plus the full rules of engagement
penenv scan --project NAME
```

The plan summary (research flag + authorisation reference) and the exact rules of
engagement given to the agent are written into the per-scan `scan_audit/<id>/` trail.
