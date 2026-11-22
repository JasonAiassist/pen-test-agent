# Profile: Business Logic & Abuse

Focus this engagement strictly on business-logic flaws - the class automated
scanners miss and that matters most for SaaS revenue and abuse. Provide
proof-of-work evidence for every confirmed finding; never trigger irreversible
transactions beyond a reversible minimum.

Areas to test:

1. **Price & quantity manipulation**
   - Negative quantities, zero/negative totals, currency or unit mismatches,
     client-side price trust, discount/coupon stacking beyond policy.
2. **Workflow bypass**
   - Skipping or reordering required steps (pay after delivery, confirm after
     ship, review before purchase).
   - Replaying completed steps; resubmitting forms; idempotency gaps.
3. **Quota & entitlement abuse**
   - Exceeding plan limits (uploads, API calls, seats, exports) without
     server-side enforcement.
   - Feature gating enforced only in the UI.
4. **Race conditions**
   - Parallel requests to consume a one-time resource (coupon, credit, invite,
     stock) more than once.
5. **Refund / cancellation abuse**
   - Partial refund accounting errors, double refunds, cancel-after-ship.
6. **Integrity of user-supplied workflows**
   - Tampering with server-generated state in client-side storage
     (cart, draft, token in localStorage used as authoritative state).

For each confirmed finding, document: affected endpoint(s), the exact request
sequence, response evidence, business impact, and a suggested fix. Rate
severity CRITICAL / HIGH / MEDIUM / LOW / INFO.
