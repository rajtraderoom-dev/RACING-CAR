import { describe, test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  randomUUID,
  randomBytes,
  sign,
} from "node:crypto";
import { spawnSync } from "node:child_process";
import { encodeCBOR } from "@levischuck/tiny-cbor";
const configured = !!process.env.CONTROL_TEST_DATABASE_URL;
describe(
  "Local control panel: real WebAuthn protocol and API permissions",
  { skip: !configured },
  () => {
    let app: any,
      pool: any,
      base: string,
      admin: any,
      hod: any,
      collector: any,
      dep: string,
      other: string,
      collectionRef: string;
    const pin = "728194",
      setup = "test-setup-" + randomUUID();
    const hash = (b: any) => createHash("sha256").update(b).digest();
    function credential() {
      const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
        jwk = keys.publicKey.export({ format: "jwk" });
      const cose = new Map<any, any>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(Buffer.from(jwk.x!, "base64url"))],
        [-3, new Uint8Array(Buffer.from(jwk.y!, "base64url"))],
      ]);
      return {
        keys,
        id: randomBytes(32).toString("base64url"),
        cose: Buffer.from(encodeCBOR(cose)),
        counter: 0,
      };
    }
    function registration(options: any, cred: any) {
      const data = Buffer.from(
        JSON.stringify({
          type: "webauthn.create",
          challenge: options.challenge,
          origin: "https://localhost:8443",
          crossOrigin: false,
        }),
      );
      const id = Buffer.from(cred.id, "base64url"),
        len = Buffer.alloc(2);
      len.writeUInt16BE(id.length);
      const auth = Buffer.concat([
        hash("localhost"),
        Buffer.from([0x45]),
        Buffer.alloc(4),
        Buffer.alloc(16),
        len,
        id,
        cred.cose,
      ]);
      const attestation = encodeCBOR(
        new Map<any, any>([
          ["fmt", "none"],
          ["attStmt", new Map()],
          ["authData", new Uint8Array(auth)],
        ]),
      );
      return {
        id: cred.id,
        rawId: cred.id,
        type: "public-key",
        response: {
          clientDataJSON: data.toString("base64url"),
          attestationObject: Buffer.from(attestation).toString("base64url"),
          transports: ["internal"],
        },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    }
    function assertion(
      ch: any,
      cred: any,
      origin = "https://localhost:8443",
      uv = true,
    ) {
      const cd = Buffer.from(
        JSON.stringify({
          type: "webauthn.get",
          challenge: hash(ch.message).toString("base64url"),
          origin,
          crossOrigin: false,
        }),
      );
      const count = Buffer.alloc(4);
      count.writeUInt32BE(++cred.counter);
      const auth = Buffer.concat([
        hash("localhost"),
        Buffer.from([uv ? 0x05 : 0x01]),
        count,
      ]);
      return {
        id: cred.id,
        rawId: cred.id,
        type: "public-key",
        response: {
          clientDataJSON: cd.toString("base64url"),
          authenticatorData: auth.toString("base64url"),
          signature: sign(
            "sha256",
            Buffer.concat([auth, hash(cd)]),
            cred.keys.privateKey,
          ).toString("base64url"),
        },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    }
    async function req(
      path: string,
      body: any = null,
      actor: any = null,
      expected = 200,
    ) {
      const r = await fetch(base + "/v1/" + path, {
        method: body === null ? "GET" : "POST",
        headers: {
          ...(body ? { "Content-Type": "application/json" } : {}),
          ...(actor ? { Authorization: "Bearer " + actor.token } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await r.text();
      assert.equal(r.status, expected, `${path}: ${text.slice(0, 200)}`);
      try {
        return JSON.parse(text);
      } catch {
        return text;
      }
    }
    async function proof(
      a: any,
      action: string,
      payload: any,
      overridePin = pin,
    ) {
      const ch = await req("challenge", { action, payload }, a, 201);
      return {
        challengeId: ch.id,
        pin: overridePin,
        assertion: assertion(ch, a.cred),
      };
    }
    async function adminOp(data: any) {
      return req(
        "admin",
        { data, proof: await proof(admin, "ADMIN", data) },
        admin,
        201,
      );
    }
    async function manage(data: any, status = 201) {
      return req(
        "control/manage",
        { data, proof: await proof(admin, "ADMIN", data) },
        admin,
        status,
      );
    }
    async function login(
      a: any,
      overridePin = pin,
      status = 201,
      uv = true,
      origin = "https://localhost:8443",
    ) {
      const options = await req(
        "web/login/options",
        { email: a.email, deviceId: a.deviceId },
        null,
        201,
      );
      const result = await req(
        "auth/login",
        {
          userId: a.id,
          deviceId: a.deviceId,
          proof: {
            challengeId: options.challenge.id,
            pin: overridePin,
            assertion: assertion(options.challenge, a.cred, origin, uv),
          },
        },
        null,
        status,
      );
      if (status === 201) {
        a.token = result.accessToken;
        a.refresh = result.refreshToken;
      }
      return result;
    }
    before(async () => {
      process.env.DATABASE_URL = process.env.CONTROL_TEST_DATABASE_URL;
      process.env.LOCAL_CONTROL_PANEL = "true";
      process.env.NODE_ENV = "development";
      process.env.ALLOW_UNATTESTED_DEV = "true";
      process.env.BOOTSTRAP_TOKEN_HASH = hash(setup).toString("hex");
      process.env.PORT = "0";
      const db = await import("../src/db");
      pool = db.pool;
      const m = await import("../src/main");
      app = await m.start();
      base = (await app.getUrl()).replace("0.0.0.0", "127.0.0.1");
    });
    after(async () => {
      await app?.close();
      await pool?.end();
    });
    test("first-run bootstrap requires one-time code, UV registration, and cannot be repeated", async () => {
      await req(
        "web/bootstrap/options",
        {
          setupCode: "incorrect",
          name: "Local Admin",
          email: "admin@test.invalid",
          pin,
          label: "Test PC",
        },
        null,
        401,
      );
      const options = await req(
        "web/bootstrap/options",
        {
          setupCode: setup,
          name: "Local Admin",
          email: "admin@test.invalid",
          pin,
          label: "Test PC",
        },
        null,
        201,
      );
      const cred = credential();
      const enrolled = await req(
        "web/bootstrap/verify",
        {
          setupCode: setup,
          id: options.id,
          response: registration(options.options, cred),
        },
        null,
        201,
      );
      admin = {
        id: enrolled.userId,
        deviceId: enrolled.deviceId,
        email: "admin@test.invalid",
        cred,
      };
      await req(
        "web/bootstrap/options",
        {
          setupCode: setup,
          name: "Duplicate",
          email: "another@test.invalid",
          pin,
          label: "PC",
        },
        null,
        409,
      );
      const stored = (
        await pool.query("SELECT data FROM web_registrations WHERE id=$1", [
          options.id,
        ])
      ).rows[0].data;
      assert.equal(stored.pin, undefined);
      assert.ok(stored.pinHash.startsWith("$argon2id$"));
    });
    test("login verifies signature, PIN, origin and user-verification flag", async () => {
      await login(admin, "000000", 401);
      await login(admin, pin, 401, false);
      await login(admin, pin, 401, true, "https://attacker.invalid");
      await login(admin);
      const context = await req("control/context", null, admin);
      assert.equal(context.user.role, "SUPER_ADMIN");
      assert.equal(context.device.kind, "WEB");
      assert.equal(context.device.credentialId, admin.cred.id);
    });
    test("both admin endpoints prevent disabling the last Super Admin", async () => {
      await manage(
        {
          operation: "USER_UPDATE",
          userId: admin.id,
          name: "Local Admin",
          email: admin.email,
          role: "SUPER_ADMIN",
          departmentId: null,
          active: false,
          reason: "Attempt to disable last admin",
        },
        409,
      );
      await req(
        "admin",
        {
          data: { operation: "REVOKE", userId: admin.id },
          proof: await proof(admin, "ADMIN", {
            operation: "REVOKE",
            userId: admin.id,
          }),
        },
        admin,
        409,
      );
      assert.equal(
        (await req("control/context", null, admin)).user.id,
        admin.id,
      );
    });
    test("department and user creation are real writes; action proof cannot be replayed", async () => {
      dep = randomUUID();
      other = randomUUID();
      const data = {
        operation: "DEPARTMENT",
        id: dep,
        name: "Control Test",
        dailyTarget: "1000000",
        maxHops: null,
        overdueMinutes: 60,
        gamification: false,
      };
      const p = await proof(admin, "ADMIN", data);
      await req("admin", { data, proof: p }, admin, 201);
      await req("admin", { data, proof: p }, admin, 401);
      await adminOp({ ...data, id: other, name: "Other Department" });
      hod = { id: randomUUID(), email: "hod@test.invalid" };
      collector = { id: randomUUID(), email: "collector@test.invalid" };
      for (const [a, role] of [
        [hod, "HOD"],
        [collector, "COLLECTOR"],
      ] as any)
        await adminOp({
          operation: "USER",
          id: a.id,
          name: role,
          email: a.email,
          pin,
          role,
          departmentId: dep,
        });
      const list = await req("admin/users", null, admin);
      assert.ok(list.users.some((u: any) => u.id === collector.id));
      assert.ok(list.users.every((u: any) => u.pin_hash === undefined));
    });
    test("one-time web invitation checks PIN, enrolls HOD, and cannot be reused", async () => {
      const invitation = await manage({
        operation: "INVITE_WEB",
        userId: hod.id,
        reason: "Enroll HOD for local test",
      });
      const token = invitation.enrollmentUrl.split("#enroll=")[1];
      await req(
        "web/enroll/options",
        { token, pin: "000000", label: "HOD PC" },
        null,
        401,
      );
      const options = await req(
        "web/enroll/options",
        { token, pin, label: "HOD PC" },
        null,
        201,
      );
      hod.cred = credential();
      const result = await req(
        "web/enroll/verify",
        {
          token,
          id: options.id,
          response: registration(options.options, hod.cred),
        },
        null,
        201,
      );
      hod.deviceId = result.deviceId;
      await req(
        "web/enroll/options",
        { token, pin, label: "Second PC" },
        null,
        401,
      );
      await login(hod);
      assert.equal(
        (await req("control/context", null, hod)).departments.length,
        1,
      );
    });
    test("HOD is scoped and cannot read global security/admin pages", async () => {
      await req("control/handovers?departmentId=" + dep, null, hod);
      for (const path of [
        "control/devices",
        "control/sessions",
        "control/database",
        "admin/users",
        "control/audit?departmentId=GLOBAL",
        "control/balances?departmentId=" + other,
        "control/discrepancies?departmentId=" + other,
      ])
        await req(path, null, hod, 403);
    });
    test("Android enrollment remains compatible, and collectors cannot enter any control API", async () => {
      collector.keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      collector.deviceId = randomUUID();
      await manage({
        operation: "ENROLL_ANDROID",
        userId: collector.id,
        deviceId: collector.deviceId,
        label: "Collector phone",
        publicKey: collector.keys.publicKey
          .export({ type: "spki", format: "pem" })
          .toString(),
        reason: "Enroll a local Android test phone",
      });
      const ch = await req(
        "auth/challenge",
        {
          userId: collector.id,
          deviceId: collector.deviceId,
          action: "LOGIN",
          payload: { userId: collector.id, deviceId: collector.deviceId },
        },
        null,
        201,
      );
      const p = {
        challengeId: ch.id,
        pin,
        signature: sign(
          "sha256",
          Buffer.from(ch.message),
          collector.keys.privateKey,
        ).toString("base64"),
      };
      collector.token = (
        await req(
          "auth/login",
          { userId: collector.id, deviceId: collector.deviceId, proof: p },
          null,
          201,
        )
      ).accessToken;
      for (const path of [
        "control/context",
        "control/devices",
        "control/sessions",
        "control/database",
        "control/handovers?departmentId=" + dep,
        "control/balances?departmentId=" + dep,
        "control/audit?departmentId=" + dep,
      ])
        await req(path, null, collector, 403);
      await manage(
        {
          operation: "INVITE_WEB",
          userId: collector.id,
          reason: "Try giving collector web access",
        },
        409,
      );
    });
    test("user role changes cannot abandon custody; user edit/reset revokes sessions without logging PIN", async () => {
      const data = {
        customerName: "Synthetic control customer",
        amount: "10000",
      };
      const ch = await req(
        "challenge",
        { action: "COLLECT", payload: data },
        collector,
        201,
      );
      collectionRef = (
        await req(
          "collections",
          {
            key: randomUUID(),
            data,
            proof: {
              challengeId: ch.id,
              pin,
              signature: sign(
                "sha256",
                Buffer.from(ch.message),
                collector.keys.privateKey,
              ).toString("base64"),
            },
          },
          collector,
          201,
        )
      ).reference;
      await manage(
        {
          operation: "USER_UPDATE",
          userId: collector.id,
          name: "Collector",
          email: collector.email,
          role: "HOD",
          departmentId: other,
          active: true,
          reason: "Try moving custody to another department",
        },
        409,
      );
      await manage({
        operation: "PIN_RESET",
        userId: collector.id,
        newPin: "853197",
        reason: "Verified test PIN recovery request",
      });
      await req("me", null, collector, 401);
      const events = (
        await req("control/audit?departmentId=GLOBAL", null, admin)
      ).events;
      const reset = events.find((e: any) => e.action === "PIN_RESET");
      assert.equal(reset.after_data.newPin, undefined);
      assert.equal(reset.after_data.userId, collector.id);
    });
    test("Web HOD performs fresh-proof receipt and reconciled final approval; Super Admin cannot approve", async () => {
      const loginCh = await req(
        "auth/challenge",
        {
          userId: collector.id,
          deviceId: collector.deviceId,
          action: "LOGIN",
          payload: { userId: collector.id, deviceId: collector.deviceId },
        },
        null,
        201,
      );
      collector.token = (
        await req(
          "auth/login",
          {
            userId: collector.id,
            deviceId: collector.deviceId,
            proof: {
              challengeId: loginCh.id,
              pin: "853197",
              signature: sign(
                "sha256",
                Buffer.from(loginCh.message),
                collector.keys.privateKey,
              ).toString("base64"),
            },
          },
          null,
          201,
        )
      ).accessToken;
      const data = {
          receiverId: hod.id,
          allocations: [{ collectionId: collectionRef, amount: "10000" }],
        },
        ch = await req(
          "challenge",
          { action: "HANDOVER", payload: data },
          collector,
          201,
        );
      const transfer = await req(
        "handovers",
        {
          key: randomUUID(),
          data,
          proof: {
            challengeId: ch.id,
            pin: "853197",
            signature: sign(
              "sha256",
              Buffer.from(ch.message),
              collector.keys.privateKey,
            ).toString("base64"),
          },
        },
        collector,
        201,
      );
      const receipt = { actual: "10000", decision: "ACCEPT" };
      await req(
        "handovers/" + transfer.reference + "/receipt",
        {
          key: randomUUID(),
          data: receipt,
          proof: await proof(hod, "RECEIPT", {
            id: transfer.reference,
            ...receipt,
          }),
        },
        hod,
        201,
      );
      const review = { decision: "APPROVE" };
      await req(
        "collections/" + collectionRef + "/review",
        {
          key: randomUUID(),
          data: review,
          proof: await proof(admin, "REVIEW", { id: collectionRef, ...review }),
        },
        admin,
        403,
      );
      await req(
        "collections/" + collectionRef + "/review",
        {
          key: randomUUID(),
          data: review,
          proof: await proof(hod, "REVIEW", { id: collectionRef, ...review }),
        },
        hod,
        201,
      );
      const chain = await req("control/chain/" + collectionRef, null, hod);
      assert.equal(chain.collection.state, "APPROVED");
      assert.equal(chain.collection.customerName, "Synthetic control customer");
      assert.equal(chain.ledger.length, 2);
    });
    test("session and device revocation apply immediately", async () => {
      const first = { ...hod };
      const context = await req("control/context", null, first);
      await login(hod);
      await manage({
        operation: "REVOKE_SESSION",
        sessionId: context.sessionId,
        reason: "Revoke one HOD test session",
      });
      await req("me", null, first, 401);
      await req("me", null, hod);
      await manage({
        operation: "REVOKE_DEVICE",
        deviceId: hod.deviceId,
        reason: "Revoke the HOD browser test device",
      });
      await req("me", null, hod, 401);
      await req("auth/refresh", { refreshToken: hod.refresh }, null, 401);
    });
    test("database controls and global audit CSV are manager-protected and do not expose secrets", async () => {
      const db = await req("control/database", null, admin);
      assert.equal(db.schemaVersion, 4);
      assert.ok(db.counts.some((r: any) => r.table === "cash_collections"));
      assert.equal(db.password, undefined);
      const payload = { kind: "AUDIT", departmentId: "GLOBAL" };
      const csv = await req(
        "control/audit-export",
        {
          departmentId: "GLOBAL",
          proof: await proof(admin, "EXPORT", payload),
        },
        admin,
        201,
      );
      assert.ok(csv.startsWith("sequence,time"));
      assert.ok(!csv.includes("853197"));
    });
    test("archived departments reject new accounts; data remains readable", async () => {
      const id = randomUUID();
      await adminOp({
        operation: "DEPARTMENT",
        id,
        name: "Archive Test",
        dailyTarget: "10000",
        maxHops: 2,
        overdueMinutes: 30,
        gamification: false,
      });
      await manage({
        operation: "ARCHIVE_DEPARTMENT",
        departmentId: id,
        active: false,
        reason: "Archive an empty testing department",
      });
      const data = {
        operation: "USER",
        id: randomUUID(),
        name: "No account",
        email: "blocked@test.invalid",
        pin,
        role: "COLLECTOR",
        departmentId: id,
      };
      await req(
        "admin",
        { data, proof: await proof(admin, "ADMIN", data) },
        admin,
        409,
      );
      await manage({
        operation: "ARCHIVE_DEPARTMENT",
        departmentId: id,
        active: true,
        reason: "Restore the empty testing department",
      });
    });
    test("web routes and existing web tokens fail closed in production", async () => {
      process.env.NODE_ENV = "production";
      try {
        await req("web/status", null, null, 403);
        await req("control/context", null, admin, 403);
        await req("me", null, admin, 401);
        await req("auth/refresh", { refreshToken: admin.refresh }, null, 401);
      } finally {
        process.env.NODE_ENV = "development";
      }
    });
    test("local operator recovery is audited, revokes old keys and supports a new passkey; production blocks it", async () => {
      const input = JSON.stringify({
        email: admin.email,
        reason: "Local owner lost the enrolled test passkey",
        newPin: null,
      });
      const blocked = spawnSync(process.execPath, ["dist/recover-local.js"], {
        input,
        encoding: "utf8",
        env: { ...process.env, NODE_ENV: "production" },
      });
      assert.equal(blocked.status, 1);
      const recovered = spawnSync(process.execPath, ["dist/recover-local.js"], {
        input,
        encoding: "utf8",
        env: process.env,
      });
      assert.equal(recovered.status, 0, recovered.stderr);
      const token = JSON.parse(recovered.stdout).enrollmentUrl.split(
        "#enroll=",
      )[1];
      await req("me", null, admin, 401);
      const options = await req(
        "web/enroll/options",
        { token, pin, label: "Recovered PC" },
        null,
        201,
      );
      admin.cred = credential();
      const result = await req(
        "web/enroll/verify",
        {
          token,
          id: options.id,
          response: registration(options.options, admin.cred),
        },
        null,
        201,
      );
      admin.deviceId = result.deviceId;
      await login(admin);
      const events = (
        await req("control/audit?departmentId=GLOBAL", null, admin)
      ).events;
      assert.ok(
        events.some(
          (e: any) =>
            e.action === "LOCAL_OPERATOR_RECOVERY" &&
            e.after_data.source === "LOCAL_DOCKER_OPERATOR",
        ),
      );
    });
    test("control static bundle is served with no-store and a self-only script policy", async () => {
      const r = await fetch(base + "/control/");
      assert.equal(r.status, 200);
      assert.equal(r.headers.get("cache-control"), "no-store");
      assert.ok(
        r.headers.get("content-security-policy")?.includes("script-src 'self'"),
      );
      assert.ok((await r.text()).includes("Racing Speed — Local Control"));
    });
  },
);
