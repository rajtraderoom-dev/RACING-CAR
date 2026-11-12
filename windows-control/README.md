# Racing Speed — Windows Backend, Database & Admin Control Panel

A separate local testing package for your **Windows computer**. It includes a browser control panel, NestJS backend, a separate persistent PostgreSQL database, and Windows setup/backup scripts. It works with the existing Racing Speed debug Android APK.

**Local testing only. Use test cash. This is not production-ready.** No default administrator, shared password, sample financial records, production secrets or private signing keys are shipped.

## Start here — Windows

1. Install **Docker Desktop for Windows** from https://www.docker.com/products/docker-desktop/ . Enable its WSL 2 backend and **Linux containers**. Start Docker Desktop and wait until the engine is running. A Windows 10/11 installation supported by Docker Desktop and CPU virtualization are required.
2. Download `Racing-Speed-Windows-Control.zip` and choose **Extract All**. Keep the whole extracted folder together; do not run the scripts from inside the ZIP.
3. Double-click **`Setup-Windows.cmd`**. First setup downloads/builds the containers; internet access is required. Node.js, Python and PostgreSQL do **not** need separate installation on Windows.
4. The script shows the fingerprint of a **locally generated test HTTPS certificate**. Type **`TRUST`** only if this is your own test setup. It installs that CA into your Windows account's trusted-root store so Edge/Chrome and Windows Hello can use HTTPS localhost. It does not modify the global PowerShell execution policy.
5. The script prints your **one-time setup code** and opens **https://localhost:8443/control/**. Paste the code, enter your name/email, choose a **6–12 digit app PIN**, then enroll **Windows Hello or a user-verifying passkey/security key**.
6. Sign in with your email, app PIN and enrolled Windows Hello/passkey. You are the first **Super Admin**. The empty database is real; create your first department to begin.

Use a current **Microsoft Edge or Google Chrome**. Set up Windows Hello in **Windows Settings → Accounts → Sign-in options** if needed. A passkey-capable security key with user verification is another option.

**Your Racing Speed app PIN is separate from your Windows Hello PIN.** The browser asks for both checks. Windows Hello may verify using a fingerprint, face, or its Windows PIN; WebAuthn verifies the UV result but cannot prove to this server which of those methods was used. Browser verification is explicitly a local-test path and is disabled in production mode. It is not a claim that the original Android biometric requirement has been certified.

## Everyday shortcuts

| Double-click | Purpose |
|---|---|
| `Start-Backend.cmd` | Start the existing database/backend and open the panel |
| `Stop-Backend.cmd` | Stop services; retain your records and certificate volumes |
| `Status.cmd` | Show container health and troubleshooting commands |
| `Backup-Database.cmd` | Save a timestamped PostgreSQL backup under `backups` |
| `Restore-Database.cmd` | Explicit recovery from a chosen backup; requires typing `RESTORE` |
| `Recover-Admin-Access.cmd` | Local Docker-owner recovery if the Super Admin loses a passkey/PIN |
| `Trust-Local-Certificate.cmd` | Install the locally generated test CA after explicit confirmation |
| `Test-Backend.cmd` | Build/run the automated suite in separate temporary test databases |

Keep Docker Desktop running while using the panel or Android app. Closing a browser tab does not stop the server. Stopping services does not delete records. Do not run `docker compose down -v` unless you deliberately intend to erase the local database/TLS volumes.

## All admin controls included

### Race Control and cash operations

- Department selector, today's collection income and target gauge, approved percentage, collector-held cash, dispute flags, overdue custody alerts, Pit Lane and 30-day trends.
- Collection search/filter across the latest 500 loaded records and full per-reference custody chains.
- Handovers with expected versus original counted amounts; HOD receipt confirmation, accept/dispute/reject, and fresh proof for every decision.
- HOD-only final approval, discrepancy or rejection with required reasons.
- Explicit discrepancy resolution after verified full recount, confirmed physical return, or review clearance. Funds stay blocked until resolved. No invisible shortage write-off is provided.
- Current custody/reserved/blocked/available balances by holder. Overdue collection age starts at the original collection time, so waiting to initiate a handover does not hide late cash.
- Audited post-approval adjustment inserts. Approved original amounts, approvals, custody and ledger history cannot be edited or deleted.
- Private receipt attachment upload/download when S3/KMS is configured. Local test setup leaves that optional external storage disabled rather than serving unencrypted/public photos.

### Users, roles and security

- Create individual Super Admin, HOD and Collector accounts with chosen PINs.
- Edit names/email, enable/disable users, and change roles/departments subject to custody safeguards.
- Retain at least one active Super Admin. A user's role/department cannot change while that account holds custody or has pending/disputed transfers.
- Reset app PINs with a mandatory reason and revoke existing sessions.
- Issue one-time, 24-hour browser-enrollment invitations for HOD/Super Admin accounts. Invitations require the recipient's app PIN and a new passkey; five wrong invitation PIN attempts disable that invitation.
- Enroll an Android P-256 public key exported by the existing APK, using an account ID and device ID. Local enrollment never claims verified hardware attestation.
- Inspect device metadata and revoke a device and its sessions. Use another enrolled admin device to revoke your current device.
- View and revoke sessions immediately. Access tokens live for two minutes; refresh tokens rotate and replay revokes their session. Browser tokens stay in memory.

### Department, audit and database controls

- Create/configure daily collection targets, authorized collector hop limits (`blank = unlimited`), and overdue thresholds.
- Archive/restore unused departments with reasons; historical records are retained. Optional gamification configuration is stored; actual badge awards are not enabled.
- Separate department and global account/security audit views with before/after metadata and chained hashes.
- Fresh-proof collection CSV exports (up to 100,000 rows; larger reports refused) and clearly bounded latest-500 audit CSV exports.
- Database connection/version/schema health and row-count inventory for Super Admin.
- Local operator backup, explicit restore, and audited break-glass account recovery scripts. The web app intentionally exposes no unrestricted SQL editor, database password, silent delete or approved-record rewrite control.

The browser cannot apply Android `FLAG_SECURE`; desktop screenshots cannot be prevented by this web panel. It uses no-store responses, a self-only script policy, escaped dynamic text, in-memory financial records, PIN/passkey action confirmation and two-minute idle lock. Browser storage contains only sign-in email/device IDs and hashed idempotency metadata, not ledger records or authentication tokens.

## Roles

| Role | Browser access |
|---|---|
| **Super Admin** | All departments; users, roles, device/session controls, policies, reports, audit and database health. Cannot perform HOD final approval. |
| **HOD** | Own department only; records, custody, incoming receipt, approval/discrepancy decisions, reports and department audit. Cannot manage users/devices or read global security audit. |
| **Collector** | **Denied** by the server for every control-panel API. Uses the Android task screen only. |

Hiding navigation is not the security boundary: the API checks roles, department scope, sessions and devices, with PostgreSQL RLS as an additional barrier.

## Connect the existing Android debug APK

1. In the panel, create a department, a Collector account, and an HOD account. Note each account ID from **Users & roles**. Only the HOD approves final cash.
2. For browser HOD access, use **Users & roles → Web access**, then open its one-time link on the Windows computer hosting this server, ideally in the HOD's separate browser profile. Enter that account's PIN and enroll its own passkey. There are no shared admin credentials.
3. On the Android test phone, open the existing Racing Speed debug APK → **Set up this device**. It creates a per-use biometric signing key and displays its public key.
4. As Super Admin, choose **Devices → Enroll Android device**. Select the account, keep/copy the generated device UUID, give it a label, paste the public key, enter a reason, then confirm with your fresh admin PIN and Windows Hello.
5. The server intentionally binds only Windows loopback. To connect a physical Android phone, install the official Android SDK Platform Tools from https://developer.android.com/tools/releases/platform-tools , enable USB debugging on your test phone and connect it by USB. Run `adb reverse tcp:8443 tcp:8443` (use `adb -s SERIAL reverse ...` when multiple phones are attached).
6. Copy **`runtime/local-test-ca.crt`** to the phone and install it as a **CA certificate** in Android security/credential settings. This is the public local test CA; never copy the private Caddy CA key. The debug APK permits user-installed CAs; release builds do not.
7. In the debug APK, set **Local test server (HTTPS)** to **`https://localhost:8443/`**, enter the account ID and enrolled device ID, and use the account PIN plus strong Android biometric.
8. Android emulator: use **`https://10.0.2.2:8443/`** and install the same test CA in that emulator. Keep the browser control panel on **localhost**, because passkeys are bound to that RP ID.

Fund-holding accounts cannot be repurposed for a different person/department. This local package does not include a closed-period/HOD succession or bank-deposit closeout workflow; keep historical accounts rather than using unsafe edits to bypass that limit.

The panel is a manager control surface. It does not fabricate collections on behalf of collectors. A real test flow is Collector → optional collector hops → HOD physical receipt → HOD approval. Internal transfers change custody, never collection income.

The existing APK is available in the parent GitHub repository's `downloads` folder. No Android rebuild is required for this compatible API.

## Separate database and service layout

```
Edge/Chrome → https://localhost:8443/control/
                        │ TLS 1.3
                  Caddy gateway
                        │ private Docker network
              NestJS API + static control panel
                        │ runtime DB account (NOSUPERUSER NOBYPASSRLS)
                 PostgreSQL 17
                 persistent named volume
```

- Docker Compose project: `racing-speed-control`.
- Database: `racing_speed_control`, separate from the earlier test package.
- Backend image: `racing-speed-control:local`.
- Schema migrations: 001–004 in `backend/migrations`.
- The `init` service alone receives the migration-owner credentials. The running API receives only the constrained `racing_api` database connection.
- PostgreSQL and API ports are not published. Only gateway port **8443 on 127.0.0.1** is exposed.
- TLS and data use different Docker volumes. The initialization step does not recreate an existing database.

`Setup-Windows.cmd` generates private random secrets in `.env` and a first-setup code in `.setup-code.txt`, then tightens their Windows file permissions. `.env`, `.setup-code.txt`, `runtime`, `backups`, and private credentials are excluded from source control and distribution. Never upload those generated files to GitHub. Keep the same folder and `.env` with its database; when updating the package, preserve your existing local configuration and take a backup first.

## Backup, restore and account recovery

**Backup:** run `Backup-Database.cmd`; it creates a PostgreSQL custom-format `.dump` in `backups` and restricts its Windows permissions. Copy it to your approved encrypted storage. A pg_dump file is not itself encrypted. Backups contain user and financial records.

**Restore:** take a current backup first. Run `Restore-Database.cmd`, supply the full backup path, and explicitly type `RESTORE`. It stops the API, restores the database, reapplies migrations/runtime grants and restarts the services. A failed restore leaves the API stopped for diagnosis. Validate trusted audit-head checkpoints and account/device access before resuming.

**Lost Super Admin access:** the Windows/Docker owner can run `Recover-Admin-Access.cmd`, enter the existing Super Admin email and a reason, explicitly type `RECOVER`, and optionally enter a new app PIN. It revokes old browser keys/sessions, writes `LOCAL_OPERATOR_RECOVERY` to the audit chain and returns a one-time enrollment link. The link still requires the account PIN. This is an OS/operator break-glass action, never an unauthenticated HTTP recovery API; it is refused in production mode. Trusting your Windows/Docker owner is unavoidable: that owner can also operate PostgreSQL and restore backups.

To remove the test CA later, inspect its fingerprint in `runtime/local-test-ca.crt`, open `certmgr.msc`, and remove only the matching Caddy test root from **Current User → Trusted Root Certification Authorities**. Deleting the TLS Docker volume creates a new CA and requires explicit re-trust.

## Developer checks

Run **`Test-Backend.cmd`** for the automated suite. It uses `compose.tests.yaml` with its own temporary PostgreSQL service and database names; it never connects to your real local control database. Test-container cleanup removes only that separate test project's temporary data.

Host development (Node 22+): `cd backend`, `npm ci`, `npm run build`. The build compiles TypeScript and bundles the browser's WebAuthn client locally with esbuild—no CDN scripts or fonts are required. The automated test suite must use freshly initialized, dedicated databases and a non-superuser runtime role. `backend/test/run.mjs` is the container harness; it accepts only its isolated `test-db` service.

Browser automation tools are unavailable in this managed build environment. Backend protocol/API tests use cryptographically signed WebAuthn fixtures; they do not claim to test a real Windows Hello sensor, security key, browser layout or native Windows execution. Follow `docs/WINDOWS-ACCEPTANCE.md` on the target computer. See `docs/VALIDATION.md` for the actual checks performed.

## Troubleshooting

- **Docker not running / Windows containers:** start Docker Desktop, select Linux containers, enable WSL 2/virtualization, then run setup again.
- **Port 8443 is occupied:** stop the earlier Racing Speed test gateway or the other application using that port. Keep this package's hostname/port unchanged so passkey origins stay consistent.
- **Browser certificate error / Windows Hello unavailable:** run `Trust-Local-Certificate.cmd`, confirm the local certificate fingerprint, restart Edge/Chrome and visit exactly `https://localhost:8443/control/`. Do not use the file:// HTML page, a raw container URL, or an arbitrary LAN IP for passkeys.
- **Setup code rejected:** use the generated `.setup-code.txt` in this folder. Setup permanently closes after the first Super Admin is enrolled. Use ordinary login or explicit operator recovery afterward.
- **Changed PC/browser profile:** use an existing admin to issue a fresh web-access invitation, or operator recovery if all admin keys are lost. Copying a browser's device ID does not copy its private passkey.
- **Forgotten app PIN:** another Super Admin can reset it with a reason; otherwise use the local operator recovery script. Resetting a PIN revokes existing sessions.
- **Database authentication fails after re-extracting elsewhere:** the persistent Docker volume still has its original credentials. Preserve the original `.env` or restore from your controlled backup. Do not delete the database volume as a first troubleshooting step.
- **Photo upload disabled:** encrypted S3/KMS is optional and not provisioned by Windows local setup. Configure it deliberately through environment/secret management before use; no public/local-plaintext fallback is enabled.
- **A user/department cannot be changed:** settle outstanding custody or transfers first. These checks protect the chain; they are not missing delete buttons.
- **Need to see errors:** open PowerShell in the extracted folder and run `docker compose logs --tail 80 api gateway` and `docker compose ps`. Do not share `.env`, PINs, setup codes or financial backups in chat.

## Release boundary

This package is deliberately local-only. The browser path requires `LOCAL_CONTROL_PANEL=true` and non-production `NODE_ENV`; web routes and existing web tokens fail closed in production. Android Play Integrity/hardware-attestation requirements remain separate. Do not expose this development Compose stack to the internet. Production browser assurance, Android attestation enrollment, live Play Integrity and S3/KMS validation, OS/browser/device testing, audit anchoring, operational monitoring, load tests and an independent MASVS/backend security review remain release gates. No OWASP certification is claimed.
