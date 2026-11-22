# Profile: Authentication & Session Management

Focus this engagement strictly on authentication and session management of the
target. Attempt attacks only against endpoints you can reach without abusing
third-party services. Provide proof-of-work evidence for every confirmed
finding.

Areas to test:

1. **Credential handling**
   - Default, weak, or guessable credentials on any account (try common combos).
   - Username/email enumeration via login, registration, and password-reset
     response or timing differences.
   - Brute-force / rate-limit absence on login and reset endpoints.
2. **Session management**
   - Session tokens: predictability, entropy, fixation, invalidation on logout.
   - Missing secure/HttpOnly/SameSite flags on cookies.
   - Session reuse after password change or logout.
3. **Token & JWT issues**
   - JWT: `alg:none`, algorithm confusion (HS/RS), weak HMAC secrets, missing
     signature verification, `kid` injection, long-lived tokens without expiry.
   - Refresh-token rotation and revocation gaps.
4. **Multi-factor / recovery**
   - Reset flows that skip identity verification (predictable reset tokens).
   - Account takeover via recovery-code reuse or race conditions.
5. **Password policy**
   - Accepted trivially weak passwords, missing breach-list checks.

For each confirmed finding, document: affected endpoint, method, exact request
used, response evidence, impact, and a suggested fix. Rate severity CRITICAL /
HIGH / MEDIUM / LOW / INFO.
