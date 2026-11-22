# Profile: Data Exposure & Privacy (SaaS)

Focus this engagement strictly on information disclosure and data-protection
issues relevant to SaaS and privacy obligations. Provide proof-of-work evidence
for every confirmed finding.

Areas to test:

1. **Sensitive data in transit & at rest references**
   - Authenticated endpoints missing `Cache-Control`, leaking tokens into
     shared caches.
   - Tokens, secrets, or PII in URLs (logged by intermediaries).
2. **Secrets exposure**
   - Secrets in client bundles: API keys, third-party tokens, internal hosts
     (check main.js, .map files, config endpoints).
   - Source-map exposure in production.
   - Repository/VCS artifacts: `/.git`, `/.svn`, backup files, editor swaps.
3. **User data handling**
   - Account deletion/export completeness (leftover rows accessible after
     deletion).
   - PII returned in bulk list endpoints without need-to-know filtering.
   - Predictable export/download URLs (unauth'd guessable links).
4. **Logging & monitoring surfaces**
   - Error pages with stack traces, internal IPs, framework versions.
   - Health/metrics endpoints publicly readable (`/metrics`, `/status`).
5. **Third-party & integration leaks**
   - OAuth client IDs/secrets exposed client-side where they should be
     server-side.
   - Webhooks or callbacks accepting unsigned payloads.
6. **Enumeration via responses**
   - Exists/not-exists distinctions enabling user, tenant, or document
     discovery.

For each confirmed finding, document: affected endpoint/file, exact request,
evidence (redact actual secret values to their first 4 characters), impact, and
a suggested fix. Rate severity CRITICAL / HIGH / MEDIUM / LOW / INFO.
