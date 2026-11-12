# Acceptance on your Windows computer

Use synthetic people and test cash. This checklist validates the operating-system/browser path that cannot be exercised by Linux API protocol tests.

1. With supported Docker Desktop/WSL 2 and Linux containers running, extract the ZIP and double-click Setup-Windows.cmd. Verify that a new separate database initializes, no default account is supplied, and your private .env/setup code files are generated locally.
2. Inspect the generated CA fingerprint; explicitly type TRUST. Edge/Chrome at https://localhost:8443/control/ should show a trusted HTTPS connection. Confirm that browser scripts/fonts load without internet/CDN access after containers have been built.
3. Use your setup code to create the first Super Admin, a chosen app PIN and a Windows Hello/passkey. Verify incorrect setup codes fail and the initial setup cannot be repeated after account creation.
4. Sign in with correct PIN and the registered authenticator. Reject/cancel the Windows Hello prompt once; no session should be created. Try a wrong app PIN once; the action should fail and no record should change. Be aware that Windows Hello can choose its Windows PIN, not necessarily biometrics.
5. Create a department, HOD and collector accounts. Give the HOD a one-time browser invitation in a separate browser profile. Confirm its department selector exposes only that department and user/device/global security/database pages are absent and API-forbidden.
6. Enroll two Android test devices/account keys through Devices and connect them over USB reverse plus the public test CA. Confirm collectors see task buttons and references/status only, never ledger/customer lists, balances or reports.
7. Record a collection on a collector phone. Initiate a partial handover to another collector, then to HOD. Verify reservations, expected/actual counts, custody balances, chains and original income remain consistent.
8. Enter an actual count mismatch. Verify no automatic custody movement, affected funds are blocked, the original count remains visible, and HOD approval is refused until explicit verified resolution.
9. HOD reviews chain and approves with a fresh PIN/passkey. Confirm Super Admin cannot act as HOD and approved original records cannot be edited/deleted. Post an audited adjustment; original amount remains intact.
10. Revoke a session/device and check the affected session fails on its next API call. Edit a user and confirm sessions are revoked. Test last-Super-Admin protection and custody-blocked role/department changes.
11. Export collection and audit CSV files using fresh proof. Verify their department scope, row limits and integer-paise values. Protect the downloaded files.
12. Leave the panel idle for more than two minutes. Confirm it locks and removes financial data. Navigate away/back and verify sign-in is required. Inspect desktop screenshots independently; the web cannot apply Android FLAG_SECURE.
13. Stop and restart through the .cmd shortcuts; records must persist. Back up the test database, then deliberately test a restore into this disposable test installation. Confirm RESTORE is mandatory and audit checkpoints are reconciled afterward.
14. On a disposable admin account/test installation, use Recover-Admin-Access.cmd. Confirm old web keys/sessions fail, the event is explicitly marked LOCAL_OPERATOR_RECOVERY, and the returned one-time link still requires the account PIN.
15. Check narrow/small browser windows, keyboard-only navigation, dialog cancellation, screen-reader labels, browser zoom and table scrolling. No measured accessibility or frame-rate certification is claimed.

Record Windows version, Docker Desktop version, browser version, authenticator type and results before allowing any real-world trial. Production use requires the additional independent reviews and integrations in README.md and SECURITY-AND-PERMISSIONS.md.
