# Profile: Access Control & Multi-Tenant Isolation

Focus this engagement strictly on authorization and tenant isolation. This is
the highest-impact vulnerability class for SaaS products. Provide
proof-of-work evidence for every confirmed finding.

Areas to test:

1. **IDOR / BOLA**
   - Enumerate or perturb object identifiers (IDs, UUIDs, slugs) in URLs,
     bodies, and query strings; attempt cross-object reads and writes.
   - Sequential/numeric IDs vs. proper authorization checks on every object
     type: orders, profiles, invoices, files, messages, exports.
2. **Privilege escalation**
   - Horizontal: act as another user of the same role.
   - Vertical: access admin-only endpoints or fields as a regular user; try
     role/permission fields in registration or profile-update payloads.
3. **Multi-tenant isolation**
   - Cross-tenant data access via tenant-scoped IDs or headers.
   - Tenant switching via manipulated `X-Tenant`-style headers or subdomains.
   - Shared caches or exports leaking other tenants' rows.
4. **Function-level access control**
   - Missing server-side checks on privileged actions (DELETE /admin/export /
     user management).
   - API methods accessible with the wrong HTTP verb (POST vs GET) bypassing
     route authorization.
5. **Indirect object references**
   - Download links, file paths, and export jobs referencing objects by path
     instead of authorized handle.

For each confirmed finding, document: affected endpoint, method, the exact
cross-object request used, response evidence, impact, and a suggested fix.
Rate severity CRITICAL / HIGH / MEDIUM / LOW / INFO.
