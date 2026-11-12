# Control-panel security and permission boundary

This package targets a Windows-owned, loopback-only local test environment. The app server and database run in Linux containers. It is not a production security certification.

| Capability | Super Admin | HOD | Collector |
|---|---|---|---|
| Collections, chains, balances, discrepancies, attachments, reports | Any selected department | Own department | Denied |
| HOD physical receipt and final approval | Cannot substitute for HOD | Addressed receipt / own department approval | Android tasks only; cannot approve |
| User create/edit/status/role/PIN recovery | Allowed with fresh app PIN + passkey | Denied | Denied |
| Department targets, hop/overdue limits, archive | Allowed with fresh proof | Read own scope | Denied |
| Browser access invitations, Android device enrollment, session/device revocation | Allowed with fresh proof | Denied | Denied |
| Department audit | Any department | Own department | Denied |
| Global account/security audit and DB inventory | Allowed | Denied | Denied |
| Backup/restore and lost-all-keys recovery | Windows/Docker operator scripts, not unrestricted HTTP endpoints | No app privilege | No app privilege |

The shared Android API still denies collector financial reads. Every `/v1/control/*` route has a server-side local-mode and manager guard; administrator-only methods add a Super Admin guard. HOD department arguments are checked before reading. Financial database tables retain PostgreSQL RLS, with request context established inside transactions under a NOSUPERUSER NOBYPASSRLS login.

## Browser authentication

- Bootstrap requires a random, local one-time setup code and absence of any pre-existing Super Admin. Only its SHA-256 digest is passed to the API. Enrollment verification is serialized to prevent competing initial Super Admin creation.
- Passkey registration is checked by SimpleWebAuthn against `https://localhost:8443`, RP ID `localhost`, allowed algorithms, user presence and user verification. Device public keys/counters are stored; private keys remain with the authenticator. Local test registration uses attestation `none` and makes no hardware-attestation claim.
- Login and sensitive actions require an Argon2id-verified Racing Speed PIN plus a WebAuthn assertion with UV required. Assertions are bound to `base64url(SHA256(server action message))`. The message binds nonce, action and canonical payload digest; payloads bind references, receivers and amounts where applicable.
- Challenges expire after 60 seconds and are consumed once. Authenticator counters are updated inside the committed authentication transaction. Wrong PIN attempts with a valid key increment lockout counters; unsigned garbage cannot exhaust another account's PIN retries.
- Two-minute access tokens and rotated refresh tokens stay in browser memory. A reused old refresh token revokes the session. Role, user/device activation and session revocation are checked from PostgreSQL on every authenticated request.
- Browser storage holds only account email/device IDs and hashed pending-idempotency metadata. No ledger, balances, PINs or auth tokens are persisted in local/session storage. Pagehide and two-minute idle lock clear in-memory session and record state.
- `LOCAL_CONTROL_PANEL=true` **and** non-production `NODE_ENV` are required. Web control routes, web action proof verification and previously issued web-session tokens fail closed in production. The browser path is not an alternative production bypass for Android Play Integrity.

Windows Hello may use an OS PIN rather than biometrics. UV is not proof of which verification method was used, and passkeys can be synced/backed up depending on the authenticator. The UI and README state this limitation. Physical-device/browser testing and a separate production browser assurance design remain necessary.

## Administration safeguards

- The last active Super Admin cannot be disabled or demoted via either account-management API.
- Role/department moves are blocked while an account holds custody or has a pending/disputed transfer. Financial transactions additionally revalidate and hold share locks on the actor's current role/department; receiver eligibility is share-locked during initiation. This prevents a stale authorized request racing an administrator's role change into an inconsistent custody chain.
- User edits, PIN resets and revocations invalidate sessions. PINs/hashes, raw invitation tokens and refresh tokens never enter audit payloads.
- Web invitations are random, hashed at rest, single-use, expire after 24 hours and allow five wrong enrollment PIN attempts. Only active HOD/Super Admin accounts can enroll browser access.
- Android public keys must be P-256 EC keys. Local enrollment explicitly leaves `hardware_verified=false`. Production Android enrollment and Play Integrity verification remain separate release gates.
- Department archival keeps history and is blocked until its custody/accounts are settled. Approved collection, approval, custody-position, allocation and attachment rows remain protected by DB triggers. Ledger, receipt confirmation, audit and adjustment rows are append-only.
- Corrections are separate adjustment inserts; rejection never reverses custody implicitly. A discrepancy resolution records verified full recount/physical return evidence and preserves the original receipt count.

## Data, exports and operations

Caddy offers TLS 1.3 on loopback. Its private CA key stays in a Docker volume; only the public test CA is copied for explicit Windows/Android trust. The running API does not receive database-owner credentials. Migrations/grants run through a separate init service. Database/API ports are not published.

PostgreSQL is configured with statement logging off, no error parameter values, terse errors and no normal error statements, to avoid financial values in database error logs.

Financial reads use `Cache-Control: no-store`; Helmet applies a self-only script policy, same-origin framing policy and content-type protections. Dynamic HTML is escaped; no third-party CDN scripts/fonts are used. There is no general SQL/search/sync endpoint or public attachment URL. CSV fields are constrained or escaped against formula injection. Receipt storage requires private S3/KMS configuration and has no unencrypted fallback; further image sanitation/scanning is a release gate.

Overdue custody is based on original collection age while positive cash remains with a collector, including cash for which no handover was initiated. Internal hops do not restart that deadline or increase income.

Backups and restores are explicit Windows/Docker-owner operations. Backups contain sensitive records and are not themselves encrypted by pg_dump. Local recovery requires the operator to type RECOVER, revokes old browser devices/sessions and appends `LOCAL_OPERATOR_RECOVERY` with its source identified. The recovered account ID is recorded as the subject/administrative identity, not as evidence that its old passkey signed the recovery. There is no unauthenticated HTTP break-glass endpoint. A trusted OS/Docker owner can access database-owner credentials regardless of app RBAC; app controls do not protect against that owner.

Audit hashes are independent per department plus a global security chain. Preserve independently trusted hash heads in a WORM/external system. Unanchored hash chains and triggers cannot prevent a malicious database superuser from disabling protections. Restoring an old backup must be reconciled against external checkpoints.

## Explicit limits

No browser screenshot prevention, production attestation claims, online hosting, SMS/WhatsApp transport, financial draft cache, server-push feed, generalized shortage write-off or badge-award engine is provided. Browser tables show latest-500 views and on-demand refresh; CSV limits are stated. The managed build has no computer-use/browser tools, so browser QA was skipped rather than simulated. Windows Hello, Windows certificate prompts, PowerShell execution and real device behavior must be accepted on the target Windows computer.
