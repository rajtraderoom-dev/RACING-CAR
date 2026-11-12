import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, generateKeyPairSync, sign } from "node:crypto";
import * as argon2 from "argon2";
import { pool, tx, Actor } from "../src/db";
import { Security, canonical, hash } from "../src/security";
const sec = new Security(),
  id = randomUUID(),
  device = randomUUID(),
  dep = randomUUID();
const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const actor: Actor = {
  id,
  device_id: device,
  department_id: dep,
  role: "COLLECTOR",
  session_id: randomUUID(),
};
before(async () => {
  await pool.query("INSERT INTO departments(id,name) VALUES($1,$2)", [
    dep,
    "Extra " + dep,
  ]);
  await pool.query(
    "INSERT INTO users(id,email,name,pin_hash) VALUES($1,$2,$3,$4)",
    [id, id + "@test.invalid", "Lockout test", await argon2.hash("827461")],
  );
  await pool.query("INSERT INTO role_assignments VALUES($1,$2,$3)", [
    id,
    dep,
    "COLLECTOR",
  ]);
  await pool.query(
    "INSERT INTO devices(id,user_id,public_key,attestation_review) VALUES($1,$2,$3,$4)",
    [
      device,
      id,
      keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
      "test",
    ],
  );
});
after(() => pool.end());
test("production rejects unverified hardware even when development bypass flag is set", async () => {
  const payload = { userId: id, deviceId: device },
    ch = await sec.challenge(id, device, "LOGIN", payload);
  const old = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  try {
    await assert.rejects(
      sec.login(id, device, {
        challengeId: ch.id,
        pin: "827461",
        signature: sign(
          "sha256",
          Buffer.from(ch.message),
          keys.privateKey,
        ).toString("base64"),
      }),
      { status: 401 },
    );
  } finally {
    process.env.NODE_ENV = old ?? "development";
  }
});
test("unsigned garbage proofs cannot exhaust another user's PIN retries", async () => {
  const payload = { userId: id, deviceId: device };
  const ch = await sec.challenge(id, device, "LOGIN", payload);
  const before = (
    await pool.query("SELECT failures FROM users WHERE id=$1", [id])
  ).rows[0].failures;
  await assert.rejects(
    sec.login(id, device, {
      challengeId: ch.id,
      pin: "000000",
      signature: Buffer.alloc(64).toString("base64"),
    }),
    { status: 401 },
  );
  assert.equal(
    (await pool.query("SELECT failures FROM users WHERE id=$1", [id])).rows[0]
      .failures,
    before,
  );
});
test("failed PIN attempts persist and lock out independently of financial rollback", async () => {
  for (let i = 0; i < 5; i++) {
    const payload = { userId: id, deviceId: device },
      ch = await sec.challenge(id, device, "LOGIN", payload);
    await assert.rejects(
      sec.login(id, device, {
        challengeId: ch.id,
        pin: "000000",
        signature: sign(
          "sha256",
          Buffer.from(ch.message),
          keys.privateKey,
        ).toString("base64"),
      }),
      { status: 401 },
    );
  }
  const u = (
    await pool.query("SELECT failures,locked_until FROM users WHERE id=$1", [
      id,
    ])
  ).rows[0];
  assert.ok(u.failures >= 5);
  assert.ok(new Date(u.locked_until) > new Date());
});
test("audit digest verification uses department chain and detects changed event content", async () => {
  const a: Actor = { ...actor, role: "SUPER_ADMIN", department_id: null };
  const { audit } = await import("../src/security");
  await tx(a, (c) =>
    audit(
      c,
      a,
      dep,
      "VERIFICATION_TEST",
      null,
      { value: "100" },
      "Audit test reason",
    ),
  );
  const events = await tx(
    a,
    async (c) =>
      (
        await c.query(
          "SELECT * FROM audit_events WHERE department_id=$1 ORDER BY seq",
          [dep],
        )
      ).rows,
  );
  let prev = "GENESIS";
  for (const e of events) {
    const ev = {
      id: e.id,
      actor: e.actor_id,
      role: e.role,
      department: e.department_id,
      action: e.action,
      before: e.before_data,
      after: e.after_data,
      reason: e.reason,
      time: new Date(e.created_at).toISOString(),
    };
    assert.equal(e.prev_hash, prev);
    assert.equal(e.event_hash, hash(prev + canonical(ev)));
    assert.notEqual(
      e.event_hash,
      hash(prev + canonical({ ...ev, action: "FORGED" })),
    );
    prev = e.event_hash;
  }
});
