import {
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
} from "@nestjs/common";
import { createHash, randomBytes, randomUUID, verify } from "node:crypto";
import * as argon2 from "argon2";
import * as jwt from "jsonwebtoken";
import { PoolClient } from "pg";
import { Actor, pool } from "./db";
import { integrity } from "./integrity";
import { localPanelEnabled, verifyWeb } from "./webauthn";
export const hash = (s: string) => createHash("sha256").update(s).digest("hex");
export function canonical(v: any): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return (
    "{" +
    Object.keys(v)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonical(v[k]))
      .join(",") +
    "}"
  );
}
export function requireManager(a: Actor) {
  if (!["HOD", "SUPER_ADMIN"].includes(a.role)) throw new ForbiddenException();
}
export function dept(a: Actor, d: string) {
  if (a.role !== "SUPER_ADMIN" && a.department_id !== d)
    throw new ForbiddenException();
}
export function amount(v: unknown, zero = false): bigint {
  if (typeof v !== "string" || !/^\d{1,16}$/.test(v))
    throw new BadRequestException("Amounts must be integer paise strings");
  const n = BigInt(v);
  if (n < (zero ? 0n : 1n) || n > 9000000000000000n)
    throw new BadRequestException("Amount out of range");
  return n;
}
export type Proof = {
  challengeId: string;
  pin: string;
  signature?: string;
  assertion?: any;
  integrityToken?: string;
};
export class Security {
  async actor(token: string): Promise<Actor> {
    try {
      const p = jwt.verify(token, process.env.JWT_SECRET!, {
        algorithms: ["HS256"],
        issuer: "cashtrack",
        audience: "cashtrack-android",
      }) as any;
      const r = await pool.query(
        `SELECT u.id,r.role,r.department_id,s.device_id,s.id session_id FROM sessions s JOIN users u ON u.id=s.user_id JOIN devices d ON d.id=s.device_id JOIN role_assignments r ON r.user_id=u.id WHERE s.id=$1 AND s.user_id=$2 AND NOT s.revoked AND s.expires_at>now() AND u.active AND d.active AND s.version=u.session_version AND (d.kind='ANDROID' OR $3::boolean)`,
        [p.sid, p.sub, localPanelEnabled()],
      );
      if (!r.rowCount) throw Error();
      return r.rows[0];
    } catch {
      throw new UnauthorizedException();
    }
  }
  async challenge(
    userId: string,
    deviceId: string,
    action: string,
    payload: any,
  ) {
    const d = await pool.query(
      "SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=$1 AND d.user_id=$2 AND d.active AND u.active",
      [deviceId, userId],
    );
    if (!d.rowCount) throw new UnauthorizedException();
    const id = randomUUID(),
      nonce = randomBytes(32).toString("base64url"),
      payloadHash = hash(canonical(payload));
    await pool.query(
      `INSERT INTO challenges VALUES($1,$2,$3,$4,$5,$6,now()+interval '60 seconds',false)`,
      [id, userId, deviceId, action, payloadHash, nonce],
    );
    return {
      id,
      nonce,
      payloadHash,
      message: `cashtrack:v1:${id}:${nonce}:${action}:${payloadHash}`,
      expiresIn: 60,
    };
  }
  // Failed PIN attempts commit independently from the financial transaction.
  async verifyProof(
    a: Pick<Actor, "id" | "device_id">,
    action: string,
    payload: any,
    p: Proof,
  ) {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const u = (
        await c.query("SELECT * FROM users WHERE id=$1 FOR UPDATE", [a.id])
      ).rows[0];
      if (
        !u ||
        !u.active ||
        (u.locked_until && new Date(u.locked_until) > new Date())
      )
        throw new UnauthorizedException("Authentication unavailable");
      const ch = (
        await c.query(
          "SELECT ch.*,d.public_key,d.hardware_verified,d.kind,d.webauthn FROM challenges ch JOIN devices d ON d.id=ch.device_id WHERE ch.id=$1 AND ch.user_id=$2 AND ch.device_id=$3 AND d.active FOR UPDATE OF ch",
          [p.challengeId, a.id, a.device_id],
        )
      ).rows[0];
      let signatureValid = false;
      let pinValid = false;
      try {
        signatureValid =
          !!ch &&
          !ch.used &&
          new Date(ch.expires_at) > new Date() &&
          ch.action === action &&
          ch.payload_hash === hash(canonical(payload)) &&
          (ch.kind === "WEB"
            ? await verifyWeb(
                c,
                a.device_id,
                ch.webauthn,
                p.assertion,
                `cashtrack:v1:${ch.id}:${ch.nonce}:${action}:${ch.payload_hash}`,
              )
            : !!p.signature &&
              verify(
                "sha256",
                Buffer.from(
                  `cashtrack:v1:${ch.id}:${ch.nonce}:${action}:${ch.payload_hash}`,
                ),
                ch.public_key,
                Buffer.from(p.signature, "base64"),
              ));
        if (signatureValid) pinValid = await argon2.verify(u.pin_hash, p.pin);
      } catch {}
      let valid = signatureValid && pinValid;
      if (valid && ch.kind === "WEB" && !localPanelEnabled()) valid = false;
      if (valid && ch.kind !== "WEB")
        try {
          await integrity(
            p.integrityToken,
            `cashtrack:v1:${ch.id}:${ch.nonce}:${action}:${ch.payload_hash}`,
            ch.hardware_verified,
          );
        } catch {
          valid = false;
        }
      if (ch)
        await c.query("UPDATE challenges SET used=true WHERE id=$1", [ch.id]);
      if (!valid) {
        // A network caller without the device key must not lock out a known account.
        if (signatureValid && !pinValid)
          await c.query(
            `UPDATE users SET failures=failures+1,locked_until=CASE WHEN failures>=4 THEN now()+make_interval(secs=>LEAST(3600,power(2,LEAST(failures,12))::int)) ELSE locked_until END WHERE id=$1`,
            [a.id],
          );
        await c.query("COMMIT");
        throw new UnauthorizedException("Authentication failed");
      }
      await c.query(
        "UPDATE users SET failures=0,locked_until=NULL WHERE id=$1",
        [a.id],
      );
      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  }
  async login(userId: string, deviceId: string, p: Proof) {
    await this.verifyProof(
      { id: userId, device_id: deviceId },
      "LOGIN",
      { userId, deviceId },
      p,
    );
    const id = randomUUID(),
      refresh = randomBytes(48).toString("base64url");
    await pool.query(
      `INSERT INTO sessions(id,user_id,device_id,refresh_hash,expires_at,version) SELECT $1,id,$3,$4,now()+interval '7 days',session_version FROM users WHERE id=$2`,
      [id, userId, deviceId, hash(refresh)],
    );
    return this.tokens(userId, id, refresh);
  }
  tokens(userId: string, sid: string, refresh: string) {
    return {
      accessToken: jwt.sign({ sid }, process.env.JWT_SECRET!, {
        algorithm: "HS256",
        subject: userId,
        issuer: "cashtrack",
        audience: "cashtrack-android",
        expiresIn: "2m",
      }),
      refreshToken: refresh,
      expiresIn: 120,
    };
  }
  async refresh(refresh: string) {
    const c = await pool.connect();
    try {
      await c.query("BEGIN");
      const s = (
        await c.query(
          `SELECT s.*,u.session_version,u.active,d.active device_active,d.kind FROM sessions s JOIN users u ON u.id=s.user_id JOIN devices d ON d.id=s.device_id WHERE refresh_hash=$1 FOR UPDATE OF s`,
          [hash(refresh)],
        )
      ).rows[0];
      if (!s) {
        const reused = (
          await c.query(
            "SELECT session_id FROM refresh_token_history WHERE hash=$1",
            [hash(refresh)],
          )
        ).rows[0];
        if (reused) {
          await c.query("UPDATE sessions SET revoked=true WHERE id=$1", [
            reused.session_id,
          ]);
          await c.query("COMMIT");
        }
        throw new UnauthorizedException();
      }
      if (
        (s.kind === "WEB" && !localPanelEnabled()) ||
        s.revoked ||
        !s.active ||
        !s.device_active ||
        s.version !== s.session_version ||
        new Date(s.expires_at) < new Date()
      )
        throw new UnauthorizedException();
      await c.query(
        "INSERT INTO refresh_token_history(hash,session_id) VALUES($1,$2)",
        [hash(refresh), s.id],
      );
      const r = randomBytes(48).toString("base64url");
      await c.query("UPDATE sessions SET refresh_hash=$1 WHERE id=$2", [
        hash(r),
        s.id,
      ]);
      await c.query("COMMIT");
      return this.tokens(s.user_id, s.id, r);
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
  }
}
export async function audit(
  c: PoolClient,
  a: Actor,
  department: string | null,
  action: string,
  before: any,
  after: any,
  reason?: string,
) {
  const scope = department ?? "GLOBAL";
  await c.query(
    "INSERT INTO audit_heads(department_key,last_hash) VALUES($1,'GENESIS') ON CONFLICT DO NOTHING",
    [scope],
  );
  const prev = (
    await c.query(
      "SELECT last_hash FROM audit_heads WHERE department_key=$1 FOR UPDATE",
      [scope],
    )
  ).rows[0].last_hash;
  const event = {
    id: randomUUID(),
    actor: a.id,
    role: a.role,
    department,
    action,
    before,
    after,
    reason: reason ?? null,
    time: new Date().toISOString(),
  };
  const digest = hash(prev + canonical(event));
  await c.query(
    "INSERT INTO audit_events(id,department_id,actor_id,role,action,reason,before_data,after_data,created_at,prev_hash,event_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    [
      event.id,
      department,
      a.id,
      a.role,
      action,
      reason ?? null,
      before,
      after,
      event.time,
      prev,
      digest,
    ],
  );
  await c.query("UPDATE audit_heads SET last_hash=$1 WHERE department_key=$2", [
    digest,
    scope,
  ]);
}
