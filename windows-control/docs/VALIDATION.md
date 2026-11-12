# Validation — Windows control package v0.2.0

Build date: 12 November 2026. Tested in Linux containers; target deployment is Docker Desktop on Windows.

## Completed checks

- TypeScript backend compilation and esbuild bundling of the local browser WebAuthn client completed.
- **38 automated backend/protocol tests passed, 0 failed/skipped**, in fresh isolated PostgreSQL 17 test databases under a **NOSUPERUSER NOBYPASSRLS** runtime login, with the test process also running as the non-root container user. Raw output is in `results/backend-tests.txt`.
- The original 21 custody/auth/authorization tests remain included. They cover direct API read denial, HOD department scope, collector response minimization, self-receipt denial, concurrent idempotency/reservation, partial/combined and multi-hop cash conservation, count discrepancies, immutable approved/append-only rows, PIN lockout and replay/refresh protection.
- New WebAuthn/API tests verify real EC/COSE registration and signed assertion protocol fixtures, wrong PIN, wrong origin, missing UV, first-admin code gating/one-time bootstrap, invitation PIN/single-use handling, HOD scope, collector denial for every control route, Android enrollment compatibility, last-Super-Admin protection through both administration endpoints, custody-blocked role moves, revocation, exports, schema inventory, production denial and local operator recovery auditing.
- A passkey-authenticated HOD performs physical receipt and final approval through the shared API. Super Admin final approval is rejected.
- Additional regressions verify overdue cash is flagged even without an initiated handover, and a stale department authorization cannot commit a financial mutation.
- Windows PowerShell scripts were parsed using the official portable PowerShell 7.5.2 engine on Linux. A command-wrapper test caught and fixed advanced-parameter binding of Docker flags; forwarding of compose/profile/native backup arguments passes. This is syntax/argument validation, **not native Windows execution**. Raw result: `results/powershell-validation.txt`.
- `npm audit --omit=dev` reported zero known vulnerabilities at build time. This is not a source security review or a guarantee against undisclosed defects.

The fresh separate Compose stack was initialized through the constrained non-root image: migrations 001–004 applied, runtime role NOSUPERUSER NOBYPASSRLS was verified, all services started, and HTTPS TLS 1.3 with certificate verification served the control HTML/JS. Setup correctly remained pending and unauthenticated database control returned 401. A source-file permission problem found during this check was fixed in both runtime/test images. PostgreSQL error-log configuration suppresses query text/parameters and uses terse errors. These are HTTP/service checks, not browser QA.

## Verification limits

This managed environment exposes no browser/computer-use JavaScript tool. Under the Sites managed-environment workflow, browser QA, screenshots and improvised browser-control installation were therefore skipped. No screenshot or claim of visual browser testing is made. Static bundling/API response checks do not establish target-browser usability.

No actual Windows computer, Windows certificate store, Windows Hello sensor/security key, or attached Android biometric device is available here. Windows PowerShell 5.1 startup, certificate installation, Docker Desktop/WSL behavior, native passkey prompts, real phone SQLCipher/Keystore behavior, accessibility and rendering must be checked using `WINDOWS-ACCEPTANCE.md`. Browser user verification can be a Windows PIN; it is not proof of a biometric or hardware attestation.

No live AWS/Google credentials were used. Optional S3/KMS attachment handling, production Android Play Integrity and attestation enrollment remain unverified external integrations. The browser control path is disabled in production. No production deployment, default admin password, source-embedded private key, real customer dataset or certification is supplied.

## Before real cash

Complete native Windows/browser/Android acceptance, production authentication/attestation design, live integration checks, independent authorization/security review, audit-head external anchoring, backup/restore drills and operational monitoring. Keep this package local and use synthetic test cash until those gates are fulfilled.
