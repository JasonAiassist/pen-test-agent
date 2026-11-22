# Profile: Full SaaS Assessment (all classes)

Perform a broad penetration assessment of the target covering the major SaaS
vulnerability classes. Prioritize depth on what you confirm; keep every claim
evidence-backed with a reproducible request/response pair.

Coverage checklist:

1. **Authentication & session management** - credential handling, session
   fixation/invalidation, JWT weaknesses, reset-flow abuse.
2. **Access control** - IDOR/BOLA, horizontal and vertical privilege
   escalation, function-level authorization, multi-tenant isolation.
3. **Injection** - SQL/NoSQL, XSS (reflected/stored/DOM), SSTI, command
   injection, deserialization, path traversal, unsafe uploads.
4. **API security** - mass assignment, excessive data exposure, rate-limit
   gaps, CORS/security headers, debug and doc endpoints, GraphQL issues,
   version-skew authorization.
5. **Business logic** - price/quantity manipulation, workflow bypass, quota
   abuse, race conditions on one-time resources.
6. **Data exposure & privacy** - secrets in client bundles, sensitive data in
   URLs/caches, enumeration via error or existence responses.

Rules of engagement:

- Only test the explicitly provided target(s).
- Use non-destructive probes; never exfiltrate more data than needed to prove
  a finding; redact secret values in the report.
- For every confirmed finding: affected endpoint, method, exact request,
  response evidence, impact, concrete fix recommendation, severity
  (CRITICAL / HIGH / MEDIUM / LOW / INFO).
- Explicitly list areas checked and found secure as well.
