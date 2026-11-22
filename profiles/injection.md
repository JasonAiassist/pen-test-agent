# Profile: Injection & Content Attacks

Focus this engagement strictly on injection and content-injection classes.
Provide proof-of-work evidence for every confirmed finding; for destructive
payloads use safe, non-destructive probes only.

Areas to test:

1. **SQL / NoSQL injection**
   - Classic and blind (boolean, time-based) SQLi on search, filter, sort, and
     login parameters.
   - NoSQL operator injection (`$ne`, `$gt`, `$regex`, JSON body operators).
2. **Cross-site scripting (XSS)**
   - Reflected: URL parameters, search terms, error messages.
   - Stored: profile fields, reviews, comments, filenames, rich text.
   - DOM-based: client-side sinks (`innerHTML`, `eval`, postMessage handlers).
3. **Template & code injection**
   - SSTI in email templates, PDF/report generation, error pages (`{{7*7}}`,
     `${7*7}`).
   - Command injection in export, upload-processing, or integration features.
4. **Deserialization**
   - Unsafe deserialization of session/state objects, cookies, or API payloads.
5. **Content & header injection**
   - HTTP response splitting/CRLF, open redirects, HTML injection in emails.
   - CSV/formula injection in exports (`=cmd`).
6. **File handling**
   - Path traversal on downloads (`../`), unrestricted file upload types,
     SVG-based XSS.

For each confirmed finding, document: affected endpoint, method, exact payload,
response evidence, impact, and a suggested fix. Rate severity CRITICAL / HIGH /
MEDIUM / LOW / INFO.
