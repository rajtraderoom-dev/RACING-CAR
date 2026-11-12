import { pool } from "./db";
import { canonical, hash } from "./security";
async function main() {
  const department = process.argv[2];
  const rows = (
    await pool.query(
      "SELECT * FROM audit_events WHERE department_id IS NOT DISTINCT FROM $1 ORDER BY seq",
      [department === "GLOBAL" ? null : department],
    )
  ).rows;
  let previous = "GENESIS";
  for (const e of rows) {
    const event = {
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
    if (
      e.prev_hash !== previous ||
      hash(previous + canonical(event)) !== e.event_hash
    )
      throw Error("Audit verification failed at sequence " + e.seq);
    previous = e.event_hash;
  }
  console.log(JSON.stringify({ events: rows.length, head: previous }));
}
main().finally(() => pool.end());
