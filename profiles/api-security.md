# Profile: API & Interface Security

Focus this engagement strictly on API-level issues: contract abuse, excessive
data exposure, and interface hygiene. Provide proof-of-work evidence for every
confirmed finding.

Areas to test:

1. **Mass assignment**
   - Send unexpected fields on create/update (`role`, `isAdmin`, `tenantId`,
     `price`, `balance`, `verified`) and observe whether the server persists
     them.
2. **Excessive data exposure**
   - API responses returning more fields than the UI uses (password hashes,
     internal flags, other users' PII, stack traces).
   - Debug endpoints (`/debug`, `/actuator`, `/.env`, `/api-docs`, GraphQL
     introspection) exposed without auth.
3. **Rate limiting & anti-automation**
   - Missing or bypassable rate limits (header spoofing `X-Forwarded-For`,
     case variation, IP rotation) on expensive or sensitive operations.
4. **Security misconfiguration**
   - Permissive CORS (`Access-Control-Allow-Origin: *` with credentials).
   - Missing security headers: CSP, X-Content-Type-Options, HSTS.
   - Verbose error messages leaking framework, versions, or SQL.
5. **API hygiene**
   - Versioned endpoints with weaker checks on old versions (`/api/v1` vs
     `/api/v2`).
   - GraphQL: introspection enabled, query depth limits missing, mutations
     lacking field-level auth.
   - Inconsistent validation across endpoints for the same object.
6. **Transport & caching**
   - Sensitive data over plain HTTP; cache-control missing on authenticated
     responses.

For each confirmed finding, document: affected endpoint, method, exact request,
response evidence, impact, and a suggested fix. Rate severity CRITICAL / HIGH /
MEDIUM / LOW / INFO.
