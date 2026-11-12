# RACING-CAR

## Racing Speed — local testing

Android cash-collection and handover app with a racing dashboard and a backend evaluation implementation.

### Downloads

Open [Releases](https://github.com/rajtraderoom-dev/RACING-CAR/releases) and expand **Assets**:

- **Racing-Speed-debug.apk** — installable Android test app (Android 11+).
- **Racing-Speed-local-test.zip** — APK plus Android/backend source, database migrations, OpenAPI specification, logo assets, automated tests and setup instructions.
- **START-HERE.md** — quick start.
- **SHA256SUMS.txt** — checksums.

The source project is inside the ZIP under `Racing-Speed/`. Read its `README.md` to start the local HTTPS backend and enroll test users/devices. The debug app's **Preview Race Control** shows clearly marked sample data without a server.

### Validation and limits

21 backend tests and 2 Android UI smoke tests passed. Android lint completed with zero errors. The debug APK signature verifies; the backend container and local TLS 1.3 route were checked.

**Use test cash only. This is not production-ready.** Production hardware-attestation enrollment, physical-device biometric/SQLCipher checks, live Google/AWS integration validation and independent security review remain outstanding. No production credentials, enrolled accounts, private signing keys or real customer data are included. See the source package's `docs/VALIDATION.md` and `docs/SECURITY.md`.
