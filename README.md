# RACING-CAR

## Racing Speed — local testing

Android cash-collection and handover app with a racing dashboard and a backend evaluation implementation.

### Download files

- [Download Android APK — 81 MB](https://raw.githubusercontent.com/rajtraderoom-dev/RACING-CAR/main/downloads/Racing-Speed-debug.apk)
- [Download complete local testing package — 28 MB](https://raw.githubusercontent.com/rajtraderoom-dev/RACING-CAR/main/downloads/Racing-Speed-local-test.zip)
- [Quick-start instructions](downloads/START-HERE.md)
- [SHA-256 checksums](downloads/SHA256SUMS.txt)
- [Logo](downloads/Racing-Speed-logo.png)

You can also browse the [downloads folder](downloads). If GitHub displays a file preview, select **Download raw file**.

The source project is inside the ZIP under `Racing-Speed/`. Read its `README.md` to start the local HTTPS backend and enroll test users/devices. The debug APK requires Android 11+. Its **Preview Race Control** shows clearly marked sample data without a server.

### Validation and limits

21 backend tests and 2 Android UI smoke tests passed. Android lint completed with zero errors. The debug APK signature verifies; the backend container and local TLS 1.3 route were checked.

**Use test cash only. This is not production-ready.** Production hardware-attestation enrollment, physical-device biometric/SQLCipher checks, live Google/AWS integration validation and independent security review remain outstanding. No production credentials, enrolled accounts, private signing keys or real customer data are included. See the source package's `docs/VALIDATION.md` and `docs/SECURITY.md`.
