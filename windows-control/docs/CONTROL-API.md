# Local browser control API

All paths are relative to the same HTTPS localhost origin. Requests and responses are no-store. No CORS access is enabled. Financial values are integer paise **strings**, never JSON floating point. Existing Android `/v1` routes remain compatible.

## Setup and passkeys (local mode only)

| Method / path | Purpose |
|---|---|
| GET `/v1/web/status` | Boolean setup status, schema version and database readiness; no financial records or credentials |
| POST `/v1/web/bootstrap/options` | First Super Admin registration options; requires local setup code, name/email, chosen PIN and device label |
| POST `/v1/web/bootstrap/verify` | Verify user-present/verified registration, exact RP/origin/challenge; create the single first Super Admin |
| POST `/v1/web/login/options` | Login options for an active HOD/Super Admin browser device; email and optional remembered device UUID |
| POST `/v1/auth/login` | Verify `{userId, deviceId, proof}`; browser proof includes challenge UUID, app PIN and WebAuthn assertion |
| POST `/v1/web/enroll/options` | One-time manager invitation + account PIN → registration options |
| POST `/v1/web/enroll/verify` | Verify registration and consume invitation; return enrolled user/device IDs |
| POST `/v1/auth/refresh` | Rotate refresh token; old-token replay revokes its session |
| POST `/v1/logout` | Revoke current session |

Registration uses `attestation=none`, UV required, RP ID `localhost`, and exact expected origin `https://localhost:8443`. It does not prove hardware attestation or distinguish Windows PIN from a biometric. The local browser path is refused when NODE_ENV is production, even if LOCAL_CONTROL_PANEL is true. Previously issued web JWTs are also refused by the shared actor lookup in production.

## Reads

Every control read first verifies local mode, session/device/user validity and manager role. Department parameters are mandatory where listed; HOD can use only its own department. Collector gets 403 for all control routes.

| Method / path | Scope / result |
|---|---|
| GET `/v1/control/context` | Name/email/role, permitted departments and current device's public credential ID/transports; no private key or PIN hash |
| GET `/v1/control/handovers?departmentId=UUID` | Latest 500 full handovers with sender/receiver names and original counts |
| GET `/v1/control/discrepancies?departmentId=UUID` | Latest 500 department discrepancies |
| GET `/v1/control/balances?departmentId=UUID` | Manager-only holder totals, reserved/blocked/available amounts and overdue collection-age counts |
| GET `/v1/control/chain/UUID` | Authorized collection with named custody ledger, handovers/counts, approval, discrepancies, adjustment journal and attachment metadata |
| GET `/v1/control/audit?departmentId=UUID` | Latest 500 department audit events |
| GET `/v1/control/audit?departmentId=GLOBAL` | Super Admin-only latest 500 account/security events |
| GET `/v1/control/devices` | Super Admin-only device metadata; no public/private keys in the list |
| GET `/v1/control/sessions` | Super Admin-only session metadata; no token/refresh hashes |
| GET `/v1/control/database` | Super Admin-only connection/version/schema/count inventory; no connection string/password |
| GET `/v1/admin/users` | Super Admin-only account and role list |
| GET `/v1/admin/departments` | Super Admin-only department list |
| GET `/v1/departments/UUID/dashboard` | Manager-only totals, target, flags, confirmed-to-HOD ranking and 30-day trends |
| GET `/v1/departments/UUID/collections` | Manager-only latest-500 records |

## Sensitive actions

Get a server challenge using `POST /v1/challenge` with `{action,payload}`. Sign exactly the server message by requesting a WebAuthn assertion whose challenge is `base64url(SHA256(message))`, and submit a **fresh Racing Speed PIN** in the proof. Windows Hello/passkey user verification must succeed. Assertions are bound to action, reference and canonical payload digest; receiver/amount fields are included in handover/receipt data. One-time challenges expire after 60 seconds.

Shared financial mutations use `{key: UUID, data: {...}, proof: {...}}`. If the URL names a reference, the challenge payload is `{id: reference, ...data}`. Idempotency keys are permanently bound to actor/action/body. Browser pending-key storage contains only a hash and UUID, not the submitted financial data.

- `POST /v1/handovers/UUID/receipt` — action RECEIPT; addressed receiver only; data `{actual,decision,reason?}`. Decisions ACCEPT / DISPUTE / REJECT. Count mismatch blocks allocations and moves no custody. Reject is for declining physical receipt.
- `POST /v1/collections/UUID/review` — action REVIEW; HOD only; data `{decision,reason?}`. APPROVE requires confirmed full original HOD custody and no open issues. DISCREPANCY / REJECT require reason.
- `POST /v1/discrepancies/UUID/resolve` — action RESOLVE; HOD only; `{resolution,reason}`. RECOUNT_MATCHED / RETURN_CONFIRMED for a handover; REVIEW_CLEARED for a collection review concern.
- `POST /v1/collections/UUID/adjustments` — action ADJUST; manager only; `{delta,reason}` on approved source records. Separate immutable correction entry; no original edit.
- `POST /v1/departments/UUID/export` — action EXPORT; challenge payload `{departmentId}`; request `{proof}`; CSV up to 100,000 rows, refusing larger reports.
- `POST /v1/control/audit-export` — action EXPORT; payload `{kind:'AUDIT',departmentId:UUID|'GLOBAL'}`; body `{departmentId,proof}`; latest-500 CSV, global scope Super Admin-only.
- `POST /v1/collections/UUID/attachments` — action ATTACHMENT; manager-only optional private S3/KMS upload. Challenge `{id,sha256}` where sha256 hashes the normalized Base64 text. Request `{data: base64,proof}`. Original file-byte SHA-256 is separately stored/verified.
- `GET /v1/attachments/UUID` — manager-scoped authenticated byte download; no public URL.

## Account and configuration actions

`POST /v1/admin` requires Super Admin and action ADMIN over its submitted `data` object. It accepts:

- `DEPARTMENT`: id, name, dailyTarget (paise string), maxHops (positive integer or null), overdueMinutes, gamification.
- `USER`: id, name, email, initial PIN, role, departmentId (null only for Super Admin). Department must be active.
- `REVOKE`: userId; safeguards preserve the last active Super Admin.

`POST /v1/control/manage` likewise requires Super Admin and fresh ADMIN proof over `data`. All operations below require a reason of 8–1,000 trimmed characters:

| operation | Other data |
|---|---|
| USER_UPDATE | userId, name, email, role, departmentId, active |
| PIN_RESET | userId, newPin |
| REVOKE_DEVICE | deviceId |
| REVOKE_SESSION | sessionId |
| INVITE_WEB | userId; returns a one-time enrollment link once, never logs its raw token |
| ENROLL_ANDROID | userId, deviceId, label, exported publicKey; local test enrollment only |
| ARCHIVE_DEPARTMENT | departmentId, active |

User changes invalidate sessions, preserve an active Super Admin, and block role/department changes while custody/pending transfers remain. The financial engine rechecks/share-locks current actor permissions and receiver eligibility inside financial transactions, so an administrator's role change cannot race a stale authorization into a new custody entry. Public recovery tokens/PIN hashes are never exposed by list APIs. The operator recovery CLI is outside HTTP and is explicitly marked in audit records.

Errors: 400 validation, 401 auth/proof/expired invitation, 403 role/scope/local-mode, 404 unavailable reference, 409 state/custody/policy conflict, 429 rate limit. Detailed SQL errors and request-body/PIN logs are not exposed.
