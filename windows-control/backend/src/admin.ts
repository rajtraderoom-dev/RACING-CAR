import "dotenv/config";
import { readFile } from "node:fs/promises";
import { randomUUID, createPublicKey } from "node:crypto";
import * as argon2 from "argon2";
import { pool } from "./db";
async function main() {
  const op = process.argv[2];
  if (op === "migrate") {
    const done = await pool.query(
      "SELECT to_regclass('public.schema_migrations') t",
    );
    if (!done.rows[0].t)
      await pool.query(await readFile("migrations/001_init.sql", "utf8"));
    const version = (
      await pool.query("SELECT max(version) v FROM schema_migrations")
    ).rows[0].v;
    if (version < 2)
      await pool.query(await readFile("migrations/002_security.sql", "utf8"));
    if (version < 3)
      await pool.query(
        await readFile("migrations/003_immutability.sql", "utf8"),
      );
    if (version < 4)
      await pool.query(
        await readFile("migrations/004_control_panel.sql", "utf8"),
      );
    console.log("Schema version 4");
  } else if (op === "provision") {
    // Input comes from a mode-0600 JSON file; no secrets on command line or stdout.
    const p = JSON.parse(await readFile(process.argv[3], "utf8"));
    if (!/^\d{6,12}$/.test(p.pin)) throw Error("PIN must be 6–12 digits");
    createPublicKey(p.publicKey);
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SELECT set_config('app.role','SUPER_ADMIN',true)");
      const department =
        p.role === "SUPER_ADMIN" ? null : (p.departmentId ?? randomUUID());
      if (department)
        await c.query(
          "INSERT INTO departments(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING",
          [department, p.departmentName ?? "Operations"],
        );
      const id = p.userId ?? randomUUID(),
        device = p.deviceId ?? randomUUID();
      await c.query(
        "INSERT INTO users(id,email,name,pin_hash) VALUES($1,$2,$3,$4)",
        [
          id,
          p.email,
          p.name,
          await argon2.hash(p.pin, {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 1,
          }),
        ],
      );
      await c.query("INSERT INTO role_assignments VALUES($1,$2,$3)", [
        id,
        department,
        p.role,
      ]);
      await c.query(
        "INSERT INTO devices(id,user_id,public_key,attestation_review) VALUES($1,$2,$3,$4)",
        [
          device,
          id,
          p.publicKey,
          p.attestationReview ?? "DEVELOPMENT ONLY — not hardware attested",
        ],
      );
      if (p.hardwareVerified === true)
        await c.query("UPDATE devices SET hardware_verified=true WHERE id=$1", [
          device,
        ]);
      await c.query("COMMIT");
      console.log(
        JSON.stringify({
          userId: id,
          deviceId: device,
          departmentId: department,
        }),
      );
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  } else
    throw Error(
      "Usage: npm run migrate | npm run provision -- /path/to/private.json",
    );
}
main().finally(() => pool.end());
