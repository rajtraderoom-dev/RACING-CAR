import "dotenv/config";
import { Pool } from "pg";
import { readFile, readdir } from "node:fs/promises";
async function main() {
  const password = process.env.DB_RUNTIME_PASSWORD ?? "";
  if (!/^[a-f0-9]{32,}$/.test(password))
    throw Error("Runtime password must be random hex");
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const c = await pool.connect();
  try {
    await c.query("SELECT pg_advisory_lock(429007)");
    const files = (await readdir("migrations"))
      .filter((f) => /^\d+_.+\.sql$/.test(f))
      .sort();
    let version = 0;
    if (
      (await c.query("SELECT to_regclass('public.schema_migrations') t"))
        .rows[0].t
    )
      version = Number(
        (await c.query("SELECT max(version) v FROM schema_migrations")).rows[0]
          .v,
      );
    for (const f of files) {
      if (Number(f.split("_")[0]) > version) {
        await c.query(await readFile("migrations/" + f, "utf8"));
        console.log("Applied migration " + f.split("_")[0]);
      }
    }
    if (
      !(await c.query("SELECT 1 FROM pg_roles WHERE rolname='racing_api'"))
        .rowCount
    )
      await c.query(
        `CREATE ROLE racing_api LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`,
      );
    else
      await c.query(
        `ALTER ROLE racing_api PASSWORD '${password}' NOSUPERUSER NOBYPASSRLS`,
      );
    await c.query(
      "GRANT USAGE ON SCHEMA public TO racing_api; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO racing_api; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO racing_api; REVOKE UPDATE,DELETE ON audit_events,custody_ledger_entries,receipt_confirmations,adjustments FROM racing_api; REVOKE INSERT,UPDATE,DELETE ON schema_migrations FROM racing_api;",
    );
    console.log("Database ready. Runtime role is NOSUPERUSER NOBYPASSRLS.");
  } finally {
    await c.query("SELECT pg_advisory_unlock(429007)");
    c.release();
    await pool.end();
  }
}
main().catch(() => {
  console.error(
    "Database initialization failed. Check Docker database readiness and your local .env credentials.",
  );
  process.exitCode = 1;
});
