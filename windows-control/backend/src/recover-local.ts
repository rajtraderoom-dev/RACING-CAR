import "dotenv/config";
import { readFileSync } from "node:fs";
import { randomBytes, randomUUID } from "node:crypto";
import { z } from "zod";
import * as argon2 from "argon2";
import { pool, tx, Actor } from "./db";
import { audit, hash } from "./security";
import { requireLocalPanel, webOrigin } from "./webauthn";
async function main() {
  requireLocalPanel();
  const input = z
    .object({
      email: z.email(),
      reason: z.string().trim().min(8).max(1000),
      newPin: z
        .string()
        .regex(/^\d{6,12}$/)
        .nullable(),
    })
    .strict()
    .parse(JSON.parse(readFileSync(0, "utf8")));
  const user = (
    await pool.query(
      "SELECT u.id,u.active FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE lower(u.email)=$1 AND r.role='SUPER_ADMIN'",
      [input.email.toLowerCase()],
    )
  ).rows[0];
  if (!user) throw Error("No Super Admin account matches that email.");
  const actor: Actor = {
    id: user.id,
    role: "SUPER_ADMIN",
    department_id: null,
    device_id: randomUUID(),
    session_id: randomUUID(),
  };
  const token = randomBytes(32).toString("base64url"),
    id = randomUUID();
  const newHash = input.newPin
    ? await argon2.hash(input.newPin, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 1,
      })
    : null;
  await tx(actor, async (c) => {
    await c.query("SELECT pg_advisory_xact_lock(878878)");
    await c.query(
      "UPDATE users SET active=true,session_version=session_version+1,failures=0,locked_until=NULL,pin_hash=COALESCE($2,pin_hash) WHERE id=$1",
      [user.id, newHash],
    );
    await c.query(
      "UPDATE devices SET active=false WHERE user_id=$1 AND kind='WEB'",
      [user.id],
    );
    await c.query("UPDATE sessions SET revoked=true WHERE user_id=$1", [
      user.id,
    ]);
    await c.query("UPDATE web_invitations SET used=true WHERE user_id=$1", [
      user.id,
    ]);
    await c.query(
      "INSERT INTO web_invitations(id,user_id,issued_by,token_hash) VALUES($1,$2,$2,$3)",
      [id, user.id, hash(token)],
    );
    await audit(
      c,
      actor,
      null,
      "LOCAL_OPERATOR_RECOVERY",
      { active: user.active },
      {
        source: "LOCAL_DOCKER_OPERATOR",
        userId: user.id,
        invitationId: id,
        pinReset: !!newHash,
        oldWebDevicesRevoked: true,
      },
      input.reason,
    );
  });
  console.log(
    JSON.stringify({
      enrollmentUrl: webOrigin() + "/control/#enroll=" + token,
      expiresInHours: 24,
      message:
        "Old web devices and sessions revoked. Enroll a new passkey using the account PIN.",
    }),
  );
}
main()
  .catch((e) => {
    console.error(
      e instanceof z.ZodError
        ? "Invalid email, PIN or recovery reason."
        : e.message,
    );
    process.exitCode = 1;
  })
  .finally(() => pool.end());
