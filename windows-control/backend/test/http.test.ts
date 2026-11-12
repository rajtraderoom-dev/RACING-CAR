import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import * as jwt from "jsonwebtoken";
import { start } from "../src/main";
import { pool, Actor, tx } from "../src/db";
import { Cash } from "../src/cash";
import type { INestApplication } from "@nestjs/common";
const d = randomUUID(),
  other = randomUUID(),
  collector = randomUUID(),
  hod = randomUUID(),
  device = randomUUID(),
  session = randomUUID();
let app: INestApplication,
  base: string,
  token: string,
  hodToken: string,
  reference: string;
before(async () => {
  process.env.PORT = "0";
  app = await start();
  base = await app.getUrl();
  base = base.replace("0.0.0.0", "127.0.0.1");
  await pool.query("INSERT INTO departments(id,name) VALUES($1,$2),($3,$4)", [
    d,
    "HTTP " + d,
    other,
    "HTTP " + other,
  ]);
  for (const [id, role] of [
    [collector, "COLLECTOR"],
    [hod, "HOD"],
  ]) {
    await pool.query(
      "INSERT INTO users(id,email,name,pin_hash) VALUES($1,$2,$3,$4)",
      [id, id + "@test.invalid", role, "not-used"],
    );
    await pool.query("INSERT INTO role_assignments VALUES($1,$2,$3)", [
      id,
      d,
      role,
    ]);
    const did = id === collector ? device : randomUUID(),
      sid = id === collector ? session : randomUUID();
    await pool.query(
      "INSERT INTO devices(id,user_id,public_key,attestation_review) VALUES($1,$2,$3,$4)",
      [did, id, "unused", "test"],
    );
    await pool.query(
      "INSERT INTO sessions(id,user_id,device_id,refresh_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 day')",
      [sid, id, did, randomUUID()],
    );
    const t = jwt.sign({ sid }, process.env.JWT_SECRET!, {
      subject: id,
      issuer: "cashtrack",
      audience: "cashtrack-android",
      expiresIn: "2m",
    });
    if (id === collector) token = t;
    else hodToken = t;
  }
  reference = (
    await new Cash().collect(
      {
        id: collector,
        role: "COLLECTOR",
        department_id: d,
        device_id: device,
        session_id: session,
      },
      randomUUID(),
      { customerName: "No exposure", amount: "10000" },
    )
  ).reference;
});
after(async () => {
  await app?.close();
  await pool.end();
});
const request = (path: string, t = token, method = "GET", body?: any) =>
  fetch(base + "/v1/" + path, {
    method,
    headers: {
      Authorization: "Bearer " + t,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
test("direct HTTP: collector cannot access dashboard, collections, audit, chain, exports or attachments", async () => {
  for (const p of [
    `departments/${d}/dashboard`,
    `departments/${d}/collections`,
    `departments/${d}/audit`,
    `collections/${reference}/chain`,
    `attachments/${randomUUID()}`,
  ])
    assert.equal((await request(p)).status, 403, p);
  assert.equal(
    (await request(`departments/${d}/export`, token, "POST", {})).status,
    403,
  );
});
test("direct HTTP: HOD department scope is enforced", async () => {
  for (const p of ["dashboard", "collections", "audit"])
    assert.equal(
      (await request(`departments/${other}/${p}`, hodToken)).status,
      403,
    );
  assert.equal(
    (await request(`departments/${d}/dashboard`, hodToken)).status,
    200,
  );
});
test("collector task and status responses contain only references/status", async () => {
  const status = await (await request("status/" + reference)).json();
  assert.deepEqual(Object.keys(status).sort(), ["reference", "status"]);
  assert.deepEqual(await (await request("tasks")).json(), { tasks: [] });
});
test("unauthenticated requests rejected; cache disabled; sensitive read routes absent", async () => {
  assert.equal((await request(`departments/${d}/collections`, "")).status, 401);
  const r = await request("me");
  assert.equal(r.headers.get("cache-control"), "no-store");
  assert.equal((await request("customers")).status, 404);
  assert.equal((await request("search?q=customer")).status, 404);
});
test("PostgreSQL RLS independently hides another department from non-superuser role", async () => {
  const actor: Actor = {
    id: hod,
    role: "HOD",
    department_id: other,
    device_id: device,
    session_id: session,
  };
  const rows = await tx(actor, (c) =>
    c.query("SELECT * FROM cash_collections WHERE id=$1", [reference]),
  );
  assert.equal(rows.rowCount, 0);
  const role = (
    await pool.query(
      "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user",
    )
  ).rows[0];
  assert.equal(role.rolsuper, false);
  assert.equal(role.rolbypassrls, false);
});
