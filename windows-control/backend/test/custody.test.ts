import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pool, Actor, tx } from "../src/db";
import { Cash } from "../src/cash";
import { Security } from "../src/security";
import * as argon2 from "argon2";
const cash = new Cash(),
  security = new Security(),
  d = randomUUID(),
  other = randomUUID();
const actor = (
  role: Actor["role"],
  department_id: string | null = d,
): Actor => ({
  id: randomUUID(),
  role,
  department_id,
  device_id: randomUUID(),
  session_id: randomUUID(),
});
const c1 = actor("COLLECTOR"),
  c2 = actor("COLLECTOR"),
  c3 = actor("COLLECTOR"),
  hod = actor("HOD"),
  outsider = actor("HOD", other),
  admin = actor("SUPER_ADMIN", null);
const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
  pin = "928174";
async function collect(who = c1, value = "500000") {
  return cash.collect(who, randomUUID(), {
    customerName: "Customer",
    amount: value,
  });
}
async function send(ref: string, value = "500000", sender = c1, receiver = c2) {
  return cash.initiate(sender, randomUUID(), {
    receiverId: receiver.id,
    allocations: [{ collectionId: ref, amount: value }],
  });
}
before(async () => {
  const done = await pool.query(
    "SELECT to_regclass('public.schema_migrations') t",
  );
  if (!done.rows[0].t)
    await pool.query(await readFile("migrations/001_init.sql", "utf8"));
  await pool.query("INSERT INTO departments(id,name) VALUES($1,$2),($3,$4)", [
    d,
    "Dept " + d,
    other,
    "Dept " + other,
  ]);
  for (const a of [c1, c2, c3, hod, outsider, admin]) {
    await pool.query(
      "INSERT INTO users(id,email,name,pin_hash) VALUES($1,$2,$3,$4)",
      [a.id, a.id + "@example.test", a.role, await argon2.hash(pin)],
    );
    await pool.query("INSERT INTO role_assignments VALUES($1,$2,$3)", [
      a.id,
      a.department_id,
      a.role,
    ]);
    await pool.query(
      "INSERT INTO devices(id,user_id,public_key,attestation_review) VALUES($1,$2,$3,$4)",
      [
        a.device_id,
        a.id,
        key.publicKey.export({ type: "spki", format: "pem" }).toString(),
        "test",
      ],
    );
  }
});
after(() => pool.end());
test("collector cannot read records, dashboard, audit, chain or attachments", async () => {
  const col = await collect();
  for (const f of [
    () => cash.records(c1, d),
    () => cash.dashboard(c1, d),
    () => cash.auditLog(c1, d),
    () => cash.chain(c1, col.reference),
    () => cash.attachment(c1, randomUUID()),
  ])
    await assert.rejects(f, { status: 403 });
});
test("HOD cannot cross department", async () => {
  const col = await collect();
  await assert.rejects(cash.records(outsider, d), { status: 403 });
  await assert.rejects(cash.dashboard(outsider, d), { status: 403 });
  await assert.rejects(cash.chain(outsider, col.reference));
});
test("sender cannot accept own handover", async () => {
  const col = await collect(),
    h = await send(col.reference);
  await assert.rejects(
    cash.receipt(c1, randomUUID(), h.reference, {
      actual: "500000",
      decision: "ACCEPT",
    }),
    { status: 403 },
  );
});
test("concurrent duplicate collections create cash once and reject key reuse", async () => {
  const k = randomUUID(),
    body = { customerName: "Duplicate", amount: "10000" };
  const result = await Promise.all(
    Array.from({ length: 8 }, () => cash.collect(c1, k, body)),
  );
  assert.equal(new Set(result.map((x) => x.reference)).size, 1);
  await assert.rejects(cash.collect(c1, k, { ...body, amount: "20000" }), {
    status: 409,
  });
});
test("concurrent reservations cannot overspend", async () => {
  const col = await collect(c1, "10000");
  const rs = await Promise.allSettled([
    send(col.reference, "7000", c1, c2),
    send(col.reference, "7000", c1, c3),
  ]);
  assert.equal(rs.filter((r) => r.status === "fulfilled").length, 1);
});
test("multiple hops preserve income, final approval requires receipt, approved records immutable", async () => {
  const col = await collect();
  for (const [from, to] of [
    [c1, c2],
    [c2, c3],
    [c3, hod],
  ]) {
    const h = await send(col.reference, "500000", from, to);
    await assert.rejects(
      cash.review(hod, randomUUID(), col.reference, { decision: "APPROVE" }),
      { status: 409 },
    );
    await cash.receipt(to, randomUUID(), h.reference, {
      actual: "500000",
      decision: "ACCEPT",
    });
  }
  const chain = await cash.chain(hod, col.reference);
  assert.equal(chain.collection.amount, "500000");
  assert.equal(chain.ledger.length, 4);
  assert.equal(
    chain.positions.reduce((s, p) => s + BigInt(p.amount), 0n),
    500000n,
  );
  await cash.review(hod, randomUUID(), col.reference, { decision: "APPROVE" });
  await assert.rejects(
    tx(hod, (c) =>
      c.query("UPDATE cash_collections SET amount=1 WHERE id=$1", [
        col.reference,
      ]),
    ),
  );
  await assert.rejects(
    tx(hod, (c) =>
      c.query("DELETE FROM cash_collections WHERE id=$1", [col.reference]),
    ),
  );
  await cash.adjust(admin, randomUUID(), col.reference, {
    delta: "-100",
    reason: "Audited customer correction",
  });
  assert.equal(
    (await cash.chain(hod, col.reference)).collection.amount,
    "500000",
  );
});
test("partial and combined handovers transfer exactly once", async () => {
  const a = await collect(c1, "10000"),
    b = await collect(c1, "20000");
  const h = await cash.initiate(c1, randomUUID(), {
    receiverId: c2.id,
    allocations: [
      { collectionId: a.reference, amount: "5000" },
      { collectionId: b.reference, amount: "15000" },
    ],
  });
  const k = randomUUID();
  await Promise.all([
    cash.receipt(c2, k, h.reference, { actual: "20000", decision: "ACCEPT" }),
    cash.receipt(c2, k, h.reference, { actual: "20000", decision: "ACCEPT" }),
  ]);
  const chain = await cash.chain(hod, a.reference);
  assert.equal(
    chain.positions.find((p) => p.holder_id === c1.id).amount,
    "5000",
  );
  assert.equal(
    chain.positions.find((p) => p.holder_id === c2.id).amount,
    "5000",
  );
});
test("mismatch blocks funds without moving custody until explicit resolution", async () => {
  const col = await collect(c1, "10000"),
    h = await send(col.reference, "10000", c1, hod);
  await cash.receipt(hod, randomUUID(), h.reference, {
    actual: "9900",
    decision: "ACCEPT",
  });
  const chain = await cash.chain(hod, col.reference);
  assert.equal(chain.ledger.length, 1);
  assert.equal(chain.positions[0].blocked, "10000");
  await assert.rejects(send(col.reference, "1", c1, c2), { status: 409 });
  await assert.rejects(
    cash.review(hod, randomUUID(), col.reference, { decision: "APPROVE" }),
    { status: 409 },
  );
  await cash.resolve(hod, randomUUID(), chain.discrepancies[0].id, {
    resolution: "RECOUNT_MATCHED",
    reason: "Physical recount confirmed full expected cash",
  });
  await cash.review(hod, randomUUID(), col.reference, { decision: "APPROVE" });
});
test("rejection never reverses confirmed custody", async () => {
  const col = await collect(c1, "10000"),
    h = await send(col.reference, "10000", c1, hod);
  await cash.receipt(hod, randomUUID(), h.reference, {
    actual: "10000",
    decision: "ACCEPT",
  });
  await cash.review(hod, randomUUID(), col.reference, {
    decision: "REJECT",
    reason: "Receipt documentation requires correction",
  });
  const chain = await cash.chain(hod, col.reference);
  assert.equal(
    chain.positions.find((p) => p.holder_id === hod.id).amount,
    "10000",
  );
});
test("cancellation releases reservations without moving custody", async () => {
  const col = await collect(c1, "10000"),
    h = await send(col.reference, "10000");
  await cash.cancel(c1, randomUUID(), h.reference);
  const chain = await cash.chain(hod, col.reference);
  assert.equal(chain.positions[0].reserved, "0");
  assert.equal(chain.ledger.length, 1);
});
test("PIN plus device signature, action binding, replay protection, refresh rotation", async () => {
  const payload = { userId: c1.id, deviceId: c1.device_id };
  const ch = await security.challenge(c1.id, c1.device_id, "LOGIN", payload);
  const p = {
    challengeId: ch.id,
    pin,
    signature: sign("sha256", Buffer.from(ch.message), key.privateKey).toString(
      "base64",
    ),
  };
  const tokens = await security.login(c1.id, c1.device_id, p);
  assert.equal((await security.actor(tokens.accessToken)).id, c1.id);
  await assert.rejects(security.login(c1.id, c1.device_id, p), { status: 401 });
  const ch2 = await security.challenge(c1.id, c1.device_id, "HANDOVER", {
    amount: "10",
  });
  await assert.rejects(
    security.verifyProof(
      c1,
      "HANDOVER",
      { amount: "11" },
      {
        ...p,
        challengeId: ch2.id,
        signature: sign(
          "sha256",
          Buffer.from(ch2.message),
          key.privateKey,
        ).toString("base64"),
      },
    ),
    { status: 401 },
  );
  await security.refresh(tokens.refreshToken);
  await assert.rejects(security.refresh(tokens.refreshToken), { status: 401 });
});
test("audit and custody ledger are append-only", async () => {
  const col = await collect();
  await assert.rejects(
    tx(hod, (c) =>
      c.query(
        "UPDATE audit_events SET action='HACKED' WHERE department_id=$1",
        [d],
      ),
    ),
  );
  await assert.rejects(
    tx(hod, (c) =>
      c.query("DELETE FROM custody_ledger_entries WHERE collection_id=$1", [
        col.reference,
      ]),
    ),
  );
});

test("cash held without an initiated handover still triggers the overdue custody alert", async () => {
  const col = await collect(c1, "10000");
  await tx(hod, (c) =>
    c.query(
      "UPDATE cash_collections SET created_at=now()-interval '3 hours' WHERE id=$1",
      [col.reference],
    ),
  );
  const dash = await cash.dashboard(hod, d);
  assert.equal(dash.overdue, 1);
});

test("a stale department authorization cannot commit a financial mutation", async () => {
  await pool.query(
    "UPDATE role_assignments SET department_id=$1 WHERE user_id=$2",
    [other, c3.id],
  );
  try {
    await assert.rejects(
      cash.collect(c3, randomUUID(), {
        customerName: "Stale request",
        amount: "100",
      }),
      { status: 403 },
    );
  } finally {
    await pool.query(
      "UPDATE role_assignments SET department_id=$1 WHERE user_id=$2",
      [d, c3.id],
    );
  }
});
