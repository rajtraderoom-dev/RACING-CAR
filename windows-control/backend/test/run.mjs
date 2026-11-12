import pg from "pg";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
const owner = process.env.TEST_OWNER_URL;
if (
  !owner ||
  new URL(owner).hostname !== "test-db" ||
  new URL(owner).pathname !== "/postgres"
)
  throw Error(
    "Run through compose.tests.yaml: this harness accepts only the isolated test-db service.",
  );
const pool = new pg.Pool({ connectionString: owner });
const password = randomBytes(32).toString("hex");
const databases = ["racing_core_test", "racing_web_test"];
try {
  for (const db of databases) await pool.query("CREATE DATABASE " + db);
  await pool.query(
    `CREATE ROLE test_runtime LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`,
  );
  for (const db of databases) {
    const url = new URL(owner);
    url.pathname = "/" + db;
    const migrate = spawnSync(process.execPath, ["dist/admin.js", "migrate"], {
      stdio: "inherit",
      env: { ...process.env, DATABASE_URL: url.href },
    });
    if (migrate.status !== 0) throw Error("Migration failed");
    const scoped = new pg.Pool({ connectionString: url.href });
    await scoped.query(
      "GRANT USAGE ON SCHEMA public TO test_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO test_runtime; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO test_runtime; REVOKE UPDATE,DELETE ON audit_events,custody_ledger_entries,receipt_confirmations,adjustments FROM test_runtime;",
    );
    await scoped.end();
  }
  await pool.end();
  const result = spawnSync("npm", ["test"], {
    stdio: "inherit",
    env: {
      ...process.env,
      NODE_ENV: "development",
      ALLOW_UNATTESTED_DEV: "true",
      JWT_SECRET: randomBytes(32).toString("hex"),
      DATABASE_URL: `postgres://test_runtime:${password}@test-db:5432/racing_core_test`,
      CONTROL_TEST_DATABASE_URL: `postgres://test_runtime:${password}@test-db:5432/racing_web_test`,
    },
  });
  process.exitCode = result.status ?? 1;
} catch (error) {
  console.error(error.message);
  await pool.end().catch(() => {});
  process.exitCode = 1;
}
