import "dotenv/config";
import { Pool, PoolClient } from "pg";
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 12,
  ssl: process.env.DB_TLS === "true" ? { rejectUnauthorized: true } : undefined,
});
export type Role = "SUPER_ADMIN" | "HOD" | "COLLECTOR";
export type Actor = {
  id: string;
  role: Role;
  department_id: string | null;
  device_id: string;
  session_id: string;
};
export async function tx<T>(
  actor: Actor,
  fn: (c: PoolClient) => Promise<T>,
): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query(
      "SELECT set_config('app.role',$1,true),set_config('app.department',$2,true),set_config('app.actor',$3,true)",
      [actor.role, actor.department_id ?? "", actor.id],
    );
    const r = await fn(c);
    await c.query("COMMIT");
    return r;
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}
