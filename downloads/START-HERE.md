# Racing Speed — local testing

Install `Racing-Speed-debug.apk` on an Android 11+ test device. Open **Preview Race Control** for clearly marked sample screens without a server. This debug app is for test cash only.

Unzip `Racing-Speed-local-test.zip` for the complete Android and backend projects, logo assets, tests, schema migrations, OpenAPI specification, threat model and setup instructions. Read `Racing-Speed/README.md` to run the local HTTPS backend and enroll test users/devices. No accounts, live backend, production signing key or cloud credentials are included.

Validation: 21 backend tests and 2 Android UI smoke tests pass; Android lint reports 0 errors. The debug APK signature verifies. Live biometric/SQLCipher checks on physical devices and production attestation/integrity/storage reviews are still required before using real cash. See `docs/VALIDATION.md` in the source package.
