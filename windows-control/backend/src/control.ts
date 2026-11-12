import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Param,
  Req,
  Res,
  UseGuards,
  CanActivate,
  ExecutionContext,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  UnauthorizedException,
  NotFoundException,
} from "@nestjs/common";
import { Request, Response } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
} from "@simplewebauthn/server";
import {
  createHash,
  randomUUID,
  randomBytes,
  timingSafeEqual,
  createPublicKey,
} from "node:crypto";
import * as argon2 from "argon2";
import { z } from "zod";
import { Actor, pool, tx } from "./db";
import { Security, Proof, audit, hash, requireManager, dept } from "./security";
import { Cash } from "./cash";
import {
  requireLocalPanel,
  localPanelEnabled,
  webOrigin,
  webChallenge,
} from "./webauthn";
const security = new Security(),
  cash = new Cash();
type R = Request & { actor: Actor };
const uuid = z.uuid(),
  pin = z.string().regex(/^\d{6,12}$/),
  reason = z.string().trim().min(8).max(1000),
  name = z.string().trim().min(1).max(120);
const proof = z
  .object({
    challengeId: uuid,
    pin,
    signature: z.string().max(2048).optional(),
    assertion: z.record(z.string(), z.unknown()).optional(),
    integrityToken: z.string().max(30000).optional(),
  })
  .strict();
function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  const r = schema.safeParse(input);
  if (!r.success) throw new BadRequestException("Please check the form fields");
  return r.data;
}
const pinHash = (s: string) =>
  argon2.hash(s, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
  });
function setupCode(code: string) {
  requireLocalPanel();
  const expected = process.env.BOOTSTRAP_TOKEN_HASH ?? "";
  if (
    !/^[a-f0-9]{64}$/.test(expected) ||
    !timingSafeEqual(Buffer.from(hash(code)), Buffer.from(expected))
  )
    throw new UnauthorizedException("Setup code is incorrect");
}
const systemActor = (id: string): Actor => ({
  id,
  role: "SUPER_ADMIN",
  department_id: null,
  device_id: randomUUID(),
  session_id: randomUUID(),
});
async function registration(data: any) {
  const options = await generateRegistrationOptions({
    rpName: "Racing Speed Local Control",
    rpID: "localhost",
    userName: data.email,
    userDisplayName: data.name,
    userID: new TextEncoder().encode(data.userId),
    attestationType: "none",
    supportedAlgorithmIDs: [-7, -257],
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    timeout: 120000,
  });
  const id = randomUUID();
  await pool.query(
    "INSERT INTO web_registrations(id,challenge,data) VALUES($1,$2,$3)",
    [id, options.challenge, data],
  );
  return { id, options };
}
async function createWebDevice(
  c: any,
  userId: string,
  label: string,
  info: any,
) {
  const credential = {
    id: info.credential.id,
    publicKey: Buffer.from(info.credential.publicKey).toString("base64url"),
    counter: info.credential.counter,
    transports: info.credential.transports ?? [],
    backedUp: info.credentialBackedUp,
    deviceType: info.credentialDeviceType,
  };
  const id = randomUUID();
  await c.query(
    "INSERT INTO devices(id,user_id,public_key,attestation_review,kind,label,webauthn) VALUES($1,$2,'WEB_AUTHN','LOCAL TEST ONLY — user verification; hardware attestation not established','WEB',$3,$4)",
    [id, userId, label, credential],
  );
  return id;
}
class ManagerGuard implements CanActivate {
  async canActivate(context: ExecutionContext) {
    requireLocalPanel();
    const req = context.switchToHttp().getRequest<R>();
    req.actor = await security.actor(
      req.headers.authorization?.replace(/^Bearer /, "") ?? "",
    );
    requireManager(req.actor);
    return true;
  }
}
@Controller("v1/web")
export class WebController {
  @Get("status") async status() {
    requireLocalPanel();
    const r = await pool.query(
      "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE role='SUPER_ADMIN') configured,(SELECT max(version) FROM schema_migrations) version",
    );
    return {
      database: "connected",
      configured: r.rows[0].configured,
      schemaVersion: r.rows[0].version,
      origin: webOrigin(),
      mode: "LOCAL_TEST_ONLY",
    };
  }
  @Post("bootstrap/options") async bootstrapOptions(@Body() raw: any) {
    const b = parse(
      z
        .object({
          setupCode: z.string().max(100),
          name,
          email: z.email(),
          pin,
          label: name,
        })
        .strict(),
      raw,
    );
    setupCode(b.setupCode);
    if (
      (
        await pool.query(
          "SELECT 1 FROM role_assignments WHERE role='SUPER_ADMIN' LIMIT 1",
        )
      ).rowCount
    )
      throw new ConflictException("Initial setup is already complete");
    return registration({
      purpose: "BOOTSTRAP",
      userId: randomUUID(),
      email: b.email.toLowerCase(),
      name: b.name,
      pinHash: await pinHash(b.pin),
      label: b.label,
    });
  }
  @Post("bootstrap/verify") async bootstrapVerify(@Body() raw: any) {
    const b = parse(
      z
        .object({
          setupCode: z.string().max(100),
          id: uuid,
          response: z.record(z.string(), z.unknown()),
        })
        .strict(),
      raw,
    );
    setupCode(b.setupCode);
    return tx(systemActor(randomUUID()), async (c) => {
      await c.query("SELECT pg_advisory_xact_lock(878878)");
      if (
        (
          await c.query(
            "SELECT 1 FROM role_assignments WHERE role='SUPER_ADMIN' LIMIT 1",
          )
        ).rowCount
      )
        throw new ConflictException("Initial setup is already complete");
      const reg = (
        await c.query(
          "SELECT * FROM web_registrations WHERE id=$1 AND NOT used AND expires_at>now() FOR UPDATE",
          [b.id],
        )
      ).rows[0];
      if (!reg || reg.data.purpose !== "BOOTSTRAP")
        throw new UnauthorizedException();
      const v = await verifyRegistrationResponse({
        response: b.response as any,
        expectedChallenge: reg.challenge,
        expectedOrigin: webOrigin(),
        expectedRPID: "localhost",
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7, -257],
      });
      if (!v.verified || !v.registrationInfo.userVerified)
        throw new UnauthorizedException();
      const d = reg.data;
      await c.query(
        "INSERT INTO users(id,email,name,pin_hash) VALUES($1,$2,$3,$4)",
        [d.userId, d.email, d.name, d.pinHash],
      );
      await c.query(
        "INSERT INTO role_assignments VALUES($1,NULL,'SUPER_ADMIN')",
        [d.userId],
      );
      const deviceId = await createWebDevice(
        c,
        d.userId,
        d.label,
        v.registrationInfo,
      );
      await c.query("UPDATE web_registrations SET used=true WHERE id=$1", [
        b.id,
      ]);
      await audit(
        c,
        systemActor(d.userId),
        null,
        "LOCAL_SUPER_ADMIN_ENROLLED",
        null,
        { userId: d.userId, deviceId },
      );
      return { userId: d.userId, deviceId, status: "ENROLLED" };
    });
  }
  @Post("login/options") async loginOptions(@Body() raw: any) {
    requireLocalPanel();
    const b = parse(
      z.object({ email: z.email(), deviceId: uuid.optional() }).strict(),
      raw,
    );
    const r = (
      await pool.query(
        "SELECT u.id,d.id device_id,d.webauthn FROM users u JOIN role_assignments ra ON ra.user_id=u.id JOIN devices d ON d.user_id=u.id WHERE lower(u.email)=$1 AND u.active AND d.active AND d.kind='WEB' AND ra.role IN ('SUPER_ADMIN','HOD') AND ($2::uuid IS NULL OR d.id=$2) ORDER BY d.enrolled_at DESC LIMIT 1",
        [b.email.toLowerCase(), b.deviceId ?? null],
      )
    ).rows[0];
    if (!r)
      throw new UnauthorizedException(
        "No active control-panel device found for this account",
      );
    const ch = await security.challenge(r.id, r.device_id, "LOGIN", {
      userId: r.id,
      deviceId: r.device_id,
    });
    const options = await generateAuthenticationOptions({
      rpID: "localhost",
      challenge: webChallenge(ch.message),
      allowCredentials: [
        { id: r.webauthn.id, transports: r.webauthn.transports },
      ],
      userVerification: "required",
      timeout: 60000,
    });
    return {
      userId: r.id,
      deviceId: r.device_id,
      credentialId: r.webauthn.id,
      challenge: ch,
      options,
    };
  }
  @Post("enroll/options") async enrollOptions(@Body() raw: any) {
    requireLocalPanel();
    const b = parse(
      z
        .object({ token: z.string().min(40).max(100), pin, label: name })
        .strict(),
      raw,
    );
    const c = await pool.connect();
    let data: any;
    try {
      await c.query("BEGIN");
      const i = (
        await c.query(
          "SELECT i.*,u.email,u.name,u.pin_hash,u.active,r.role FROM web_invitations i JOIN users u ON u.id=i.user_id JOIN role_assignments r ON r.user_id=u.id WHERE token_hash=$1 FOR UPDATE OF i",
          [hash(b.token)],
        )
      ).rows[0];
      if (
        !i ||
        i.used ||
        !i.active ||
        i.attempts >= 5 ||
        new Date(i.expires_at) < new Date() ||
        !["SUPER_ADMIN", "HOD"].includes(i.role)
      )
        throw new UnauthorizedException("Invitation unavailable");
      if (!(await argon2.verify(i.pin_hash, b.pin))) {
        await c.query(
          "UPDATE web_invitations SET attempts=attempts+1 WHERE id=$1",
          [i.id],
        );
        await c.query("COMMIT");
        throw new UnauthorizedException("Incorrect PIN");
      }
      data = {
        purpose: "INVITE",
        inviteId: i.id,
        userId: i.user_id,
        name: i.name,
        email: i.email,
        label: b.label,
      };
      await c.query("COMMIT");
    } catch (e) {
      await c.query("ROLLBACK");
      throw e;
    } finally {
      c.release();
    }
    return registration(data);
  }
  @Post("enroll/verify") async enrollVerify(@Body() raw: any) {
    requireLocalPanel();
    const b = parse(
      z
        .object({
          token: z.string().min(40).max(100),
          id: uuid,
          response: z.record(z.string(), z.unknown()),
        })
        .strict(),
      raw,
    );
    return tx(systemActor(randomUUID()), async (c) => {
      const reg = (
        await c.query(
          "SELECT * FROM web_registrations WHERE id=$1 AND NOT used AND expires_at>now() FOR UPDATE",
          [b.id],
        )
      ).rows[0];
      if (!reg || reg.data.purpose !== "INVITE")
        throw new UnauthorizedException();
      const invite = (
        await c.query(
          "SELECT * FROM web_invitations WHERE id=$1 AND token_hash=$2 AND NOT used AND attempts<5 AND expires_at>now() FOR UPDATE",
          [reg.data.inviteId, hash(b.token)],
        )
      ).rows[0];
      const user = (
        await c.query(
          "SELECT u.active,r.role FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE u.id=$1",
          [reg.data.userId],
        )
      ).rows[0];
      if (
        !invite ||
        !user?.active ||
        !["HOD", "SUPER_ADMIN"].includes(user.role)
      )
        throw new UnauthorizedException();
      const v = await verifyRegistrationResponse({
        response: b.response as any,
        expectedChallenge: reg.challenge,
        expectedOrigin: webOrigin(),
        expectedRPID: "localhost",
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7, -257],
      });
      if (!v.verified || !v.registrationInfo.userVerified)
        throw new UnauthorizedException();
      const deviceId = await createWebDevice(
        c,
        reg.data.userId,
        reg.data.label,
        v.registrationInfo,
      );
      await c.query("UPDATE web_registrations SET used=true WHERE id=$1", [
        b.id,
      ]);
      await c.query("UPDATE web_invitations SET used=true WHERE id=$1", [
        invite.id,
      ]);
      await audit(
        c,
        systemActor(invite.issued_by),
        null,
        "LOCAL_WEB_DEVICE_ENROLLED",
        null,
        { userId: reg.data.userId, deviceId },
      );
      return { userId: reg.data.userId, deviceId, status: "ENROLLED" };
    });
  }
}
const management = z.discriminatedUnion("operation", [
  z
    .object({
      operation: z.literal("USER_UPDATE"),
      userId: uuid,
      name,
      email: z.email(),
      role: z.enum(["SUPER_ADMIN", "HOD", "COLLECTOR"]),
      departmentId: uuid.nullable(),
      active: z.boolean(),
      reason,
    })
    .strict(),
  z
    .object({
      operation: z.literal("PIN_RESET"),
      userId: uuid,
      newPin: pin,
      reason,
    })
    .strict(),
  z
    .object({ operation: z.literal("REVOKE_DEVICE"), deviceId: uuid, reason })
    .strict(),
  z
    .object({ operation: z.literal("REVOKE_SESSION"), sessionId: uuid, reason })
    .strict(),
  z
    .object({ operation: z.literal("INVITE_WEB"), userId: uuid, reason })
    .strict(),
  z
    .object({
      operation: z.literal("ENROLL_ANDROID"),
      userId: uuid,
      deviceId: uuid,
      label: name,
      publicKey: z.string().min(100).max(4096),
      reason,
    })
    .strict(),
  z
    .object({
      operation: z.literal("ARCHIVE_DEPARTMENT"),
      departmentId: uuid,
      active: z.boolean(),
      reason,
    })
    .strict(),
]);
@Controller("v1/control")
@UseGuards(ManagerGuard)
export class ControlController {
  @Get("context") async context(@Req() r: R) {
    return tx(r.actor, async (c) => {
      const user = (
        await c.query("SELECT id,name,email FROM users WHERE id=$1", [
          r.actor.id,
        ])
      ).rows[0];
      const departments = (
        await c.query(
          "SELECT * FROM departments WHERE ($1::boolean OR id=$2) ORDER BY active DESC,name",
          [r.actor.role === "SUPER_ADMIN", r.actor.department_id],
        )
      ).rows;
      const d = (
        await c.query("SELECT kind,webauthn,label FROM devices WHERE id=$1", [
          r.actor.device_id,
        ])
      ).rows[0];
      return {
        sessionId: r.actor.session_id,
        user: { ...user, role: r.actor.role },
        departments,
        device: {
          id: r.actor.device_id,
          kind: d.kind,
          label: d.label,
          credentialId: d.webauthn?.id,
          transports: d.webauthn?.transports ?? [],
        },
        mode: "LOCAL_TEST_ONLY",
      };
    });
  }
  @Get("handovers") async handovers(
    @Req() r: R,
    @Query("departmentId") id: string,
  ) {
    parse(uuid, id);
    dept(r.actor, id);
    return tx(r.actor, async (c) => ({
      handovers: (
        await c.query(
          "SELECT h.*,s.name sender,r.name receiver,rc.actual FROM handovers h JOIN users s ON s.id=h.sender_id JOIN users r ON r.id=h.receiver_id LEFT JOIN receipt_confirmations rc ON rc.handover_id=h.id WHERE h.department_id=$1 ORDER BY h.created_at DESC LIMIT 500",
          [id],
        )
      ).rows,
    }));
  }
  @Get("discrepancies") async discrepancies(
    @Req() r: R,
    @Query("departmentId") id: string,
  ) {
    parse(uuid, id);
    dept(r.actor, id);
    return tx(r.actor, async (c) => ({
      discrepancies: (
        await c.query(
          "SELECT * FROM discrepancies WHERE department_id=$1 ORDER BY created_at DESC LIMIT 500",
          [id],
        )
      ).rows,
    }));
  }
  @Get("balances") async balances(
    @Req() r: R,
    @Query("departmentId") id: string,
  ) {
    parse(uuid, id);
    dept(r.actor, id);
    return tx(r.actor, async (c) => ({
      balances: (
        await c.query(
          "SELECT p.holder_id,u.name,r.role,sum(p.amount)::text amount,sum(p.reserved)::text reserved,sum(p.blocked)::text blocked,sum(p.amount-p.reserved-p.blocked)::text available,count(*) FILTER(WHERE p.amount>0 AND r.role='COLLECTOR' AND cc.created_at<now()-make_interval(mins=>dp.overdue_minutes))::int overdue,min(cc.created_at) FILTER(WHERE p.amount>0) oldest FROM custody_positions p JOIN cash_collections cc ON cc.id=p.collection_id JOIN departments dp ON dp.id=p.department_id JOIN users u ON u.id=p.holder_id JOIN role_assignments r ON r.user_id=u.id WHERE p.department_id=$1 GROUP BY p.holder_id,u.name,r.role ORDER BY sum(p.amount) DESC",
          [id],
        )
      ).rows,
    }));
  }
  @Get("chain/:id") async chain(@Req() r: R, @Param("id") id: string) {
    parse(uuid, id);
    const chain = await cash.chain(r.actor, id);
    return tx(r.actor, async (c) => ({
      ...chain,
      collection: {
        ...chain.collection,
        ...(
          await c.query(
            'SELECT cu.name "customerName" FROM cash_collections cc JOIN customers cu ON cu.id=cc.customer_id WHERE cc.id=$1',
            [id],
          )
        ).rows[0],
      },
      ledger: (
        await c.query(
          "SELECT l.*,f.name from_name,t.name to_name FROM custody_ledger_entries l LEFT JOIN users f ON f.id=l.from_user JOIN users t ON t.id=l.to_user WHERE l.collection_id=$1 ORDER BY l.created_at",
          [id],
        )
      ).rows,
      approval: (
        await c.query("SELECT * FROM hod_approvals WHERE collection_id=$1", [
          id,
        ])
      ).rows[0],
      adjustments: (
        await c.query(
          "SELECT * FROM adjustments WHERE collection_id=$1 ORDER BY created_at",
          [id],
        )
      ).rows,
      attachments: (
        await c.query(
          "SELECT id,content_type,sha256,created_at FROM attachments WHERE collection_id=$1",
          [id],
        )
      ).rows,
    }));
  }
  @Get("audit") async logs(@Req() r: R, @Query("departmentId") scope: string) {
    if (scope === "GLOBAL") {
      this.super(r);
      return tx(r.actor, async (c) => ({
        events: (
          await c.query(
            "SELECT * FROM audit_events WHERE department_id IS NULL ORDER BY seq DESC LIMIT 500",
          )
        ).rows,
      }));
    }
    parse(uuid, scope);
    return { events: await cash.auditLog(r.actor, scope) };
  }
  @Get("devices") async devices(@Req() r: R) {
    this.super(r);
    return {
      devices: (
        await pool.query(
          "SELECT d.id,d.user_id,d.label,d.kind,d.active,d.enrolled_at,d.hardware_verified,d.attestation_review,u.name owner,u.email,r.role FROM devices d JOIN users u ON u.id=d.user_id JOIN role_assignments r ON r.user_id=u.id ORDER BY d.enrolled_at DESC LIMIT 1000",
        )
      ).rows,
    };
  }
  @Get("sessions") async sessions(@Req() r: R) {
    this.super(r);
    return {
      sessions: (
        await pool.query(
          "SELECT s.id,s.user_id,s.device_id,s.expires_at,s.revoked,u.name owner,d.label device FROM sessions s JOIN users u ON u.id=s.user_id JOIN devices d ON d.id=s.device_id ORDER BY s.expires_at DESC LIMIT 1000",
        )
      ).rows,
    };
  }
  @Get("database") async database(@Req() r: R) {
    this.super(r);
    return tx(r.actor, async (c) => {
      const tables = [
        "departments",
        "users",
        "devices",
        "customers",
        "cash_collections",
        "handovers",
        "custody_positions",
        "custody_ledger_entries",
        "discrepancies",
        "adjustments",
        "audit_events",
      ];
      const counts = [];
      for (const table of tables)
        counts.push({
          table,
          rows: (await c.query(`SELECT count(*)::text n FROM ${table}`)).rows[0]
            .n,
        });
      return {
        database: (
          await c.query(
            "SELECT current_database() name,pg_database_size(current_database())::text bytes,version() version",
          )
        ).rows[0],
        schemaVersion: (
          await c.query("SELECT max(version) version FROM schema_migrations")
        ).rows[0].version,
        counts,
        backups:
          "Use windows/Backup-Database.ps1; restore is an explicit local operator task.",
      };
    });
  }
  private super(r: R) {
    if (r.actor.role !== "SUPER_ADMIN")
      throw new ForbiddenException("Super Admin only");
  }
  @Post("manage") async manage(@Req() r: R, @Body() raw: any) {
    this.super(r);
    const b = parse(z.object({ data: management, proof }).strict(), raw);
    await security.verifyProof(r.actor, "ADMIN", b.data, b.proof);
    return tx(r.actor, async (c) => {
      await c.query("SELECT pg_advisory_xact_lock(878878)");
      const d = b.data;
      let after: any = {},
        before: any = null,
        scope: string | null = null;
      if (d.operation === "USER_UPDATE") {
        if ((d.role === "SUPER_ADMIN") !== (d.departmentId === null))
          throw new BadRequestException("Role and department do not match");
        const u = (
          await c.query(
            "SELECT u.id,u.name,u.email,u.active,r.role,r.department_id FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE u.id=$1 FOR UPDATE OF u,r",
            [d.userId],
          )
        ).rows[0];
        if (!u) throw new NotFoundException();
        before = u;
        if (
          u.role === "SUPER_ADMIN" &&
          u.active &&
          (!d.active || d.role !== "SUPER_ADMIN") &&
          (
            await c.query(
              "SELECT 1 FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE u.active AND r.role='SUPER_ADMIN' AND u.id<>$1",
              [d.userId],
            )
          ).rowCount === 0
        )
          throw new ConflictException("Keep at least one active Super Admin");
        if (u.role !== d.role || u.department_id !== d.departmentId) {
          if (
            (
              await c.query(
                "SELECT 1 FROM custody_positions WHERE holder_id=$1 AND amount>0 UNION ALL SELECT 1 FROM handovers WHERE (sender_id=$1 OR receiver_id=$1) AND state IN ('PENDING_RECEIPT','DISPUTED') LIMIT 1",
                [d.userId],
              )
            ).rowCount
          )
            throw new ConflictException(
              "Settle this account’s custody and handovers before changing role or department",
            );
        }
        if (d.departmentId) {
          const active = (
            await c.query("SELECT active FROM departments WHERE id=$1", [
              d.departmentId,
            ])
          ).rows[0];
          if (!active?.active)
            throw new ConflictException("Choose an active department");
        }
        await c.query(
          "UPDATE users SET name=$2,email=$3,active=$4,session_version=session_version+1 WHERE id=$1",
          [d.userId, d.name, d.email.toLowerCase(), d.active],
        );
        await c.query(
          "UPDATE role_assignments SET role=$2,department_id=$3 WHERE user_id=$1",
          [d.userId, d.role, d.departmentId],
        );
        await c.query("UPDATE sessions SET revoked=true WHERE user_id=$1", [
          d.userId,
        ]);
        after = { ...d };
        scope = d.departmentId;
      } else if (d.operation === "PIN_RESET") {
        if (
          !(await c.query("SELECT id FROM users WHERE id=$1", [d.userId]))
            .rowCount
        )
          throw new NotFoundException();
        await c.query(
          "UPDATE users SET pin_hash=$2,failures=0,locked_until=NULL,session_version=session_version+1 WHERE id=$1",
          [d.userId, await pinHash(d.newPin)],
        );
        await c.query("UPDATE sessions SET revoked=true WHERE user_id=$1", [
          d.userId,
        ]);
        after = { userId: d.userId };
      } else if (d.operation === "REVOKE_DEVICE") {
        if (d.deviceId === r.actor.device_id)
          throw new ConflictException(
            "Use another enrolled administrator device to revoke this device",
          );
        if (
          !(await c.query("SELECT id FROM devices WHERE id=$1", [d.deviceId]))
            .rowCount
        )
          throw new NotFoundException();
        await c.query("UPDATE devices SET active=false WHERE id=$1", [
          d.deviceId,
        ]);
        await c.query("UPDATE sessions SET revoked=true WHERE device_id=$1", [
          d.deviceId,
        ]);
        after = { deviceId: d.deviceId };
      } else if (d.operation === "REVOKE_SESSION") {
        if (
          !(
            await c.query(
              "UPDATE sessions SET revoked=true WHERE id=$1 RETURNING id",
              [d.sessionId],
            )
          ).rowCount
        )
          throw new NotFoundException();
        after = { sessionId: d.sessionId };
      } else if (d.operation === "INVITE_WEB") {
        const user = (
          await c.query(
            "SELECT u.active,r.role FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE u.id=$1",
            [d.userId],
          )
        ).rows[0];
        if (!user?.active || !["HOD", "SUPER_ADMIN"].includes(user.role))
          throw new ConflictException(
            "Browser access is available to active HOD and Super Admin accounts only",
          );
        const token = randomBytes(32).toString("base64url"),
          id = randomUUID();
        await c.query(
          "INSERT INTO web_invitations(id,user_id,issued_by,token_hash) VALUES($1,$2,$3,$4)",
          [id, d.userId, r.actor.id, hash(token)],
        );
        after = { invitationId: id, userId: d.userId };
        await audit(
          c,
          r.actor,
          null,
          "WEB_ACCESS_INVITED",
          null,
          after,
          d.reason,
        );
        return {
          status: "INVITED",
          enrollmentUrl: webOrigin() + "/control/#enroll=" + token,
          expiresInHours: 24,
        };
      } else if (d.operation === "ENROLL_ANDROID") {
        const key = createPublicKey(d.publicKey);
        if (
          key.asymmetricKeyType !== "ec" ||
          key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
        )
          throw new BadRequestException(
            "Use the P-256 public key exported by the Android app",
          );
        if (
          !(
            await c.query("SELECT id FROM users WHERE id=$1 AND active", [
              d.userId,
            ])
          ).rowCount
        )
          throw new NotFoundException();
        await c.query(
          "INSERT INTO devices(id,user_id,public_key,attestation_review,label) VALUES($1,$2,$3,'LOCAL DEVELOPMENT ONLY — not hardware attested',$4)",
          [d.deviceId, d.userId, d.publicKey, d.label],
        );
        after = {
          deviceId: d.deviceId,
          userId: d.userId,
          label: d.label,
          publicKeyDigest: hash(d.publicKey),
        };
      } else if (d.operation === "ARCHIVE_DEPARTMENT") {
        if (
          !d.active &&
          (
            await c.query(
              "SELECT 1 FROM role_assignments r JOIN users u ON u.id=r.user_id WHERE r.department_id=$1 AND u.active UNION ALL SELECT 1 FROM custody_positions WHERE department_id=$1 AND amount>0 LIMIT 1",
              [d.departmentId],
            )
          ).rowCount
        )
          throw new ConflictException(
            "Settle custody and move/deactivate accounts before archiving",
          );
        if (
          !(
            await c.query(
              "UPDATE departments SET active=$2 WHERE id=$1 RETURNING id",
              [d.departmentId, d.active],
            )
          ).rowCount
        )
          throw new NotFoundException();
        scope = d.departmentId;
        after = { departmentId: d.departmentId, active: d.active };
      }
      await audit(c, r.actor, scope, d.operation, before, after, d.reason);
      return { status: "DONE" };
    });
  }
  @Post("audit-export") async auditExport(
    @Req() r: R,
    @Body() raw: any,
    @Res() res: Response,
  ) {
    const b = parse(
      z
        .object({ departmentId: z.union([uuid, z.literal("GLOBAL")]), proof })
        .strict(),
      raw,
    );
    if (b.departmentId === "GLOBAL") this.super(r);
    else dept(r.actor, b.departmentId);
    await security.verifyProof(
      r.actor,
      "EXPORT",
      { kind: "AUDIT", departmentId: b.departmentId },
      b.proof,
    );
    const rows =
      b.departmentId === "GLOBAL"
        ? await tx(
            r.actor,
            async (c) =>
              (
                await c.query(
                  "SELECT * FROM audit_events WHERE department_id IS NULL ORDER BY seq DESC LIMIT 500",
                )
              ).rows,
          )
        : await cash.auditLog(r.actor, b.departmentId);
    const field = (v: any) =>
      '"' +
      String(v ?? "")
        .replace(/^[=+\-@]/, "'$&")
        .replace(/"/g, '""') +
      '"';
    await tx(r.actor, (c) =>
      audit(
        c,
        r.actor,
        b.departmentId === "GLOBAL" ? null : b.departmentId,
        "AUDIT_EXPORTED",
        null,
        { count: rows.length },
      ),
    );
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="racing-speed-audit.csv"',
    );
    res.send(
      [
        "sequence,time,actor,role,action,reason,previous_hash,event_hash",
        ...rows.map((x) =>
          [
            x.seq,
            x.created_at.toISOString(),
            x.actor_id,
            x.role,
            x.action,
            x.reason,
            x.prev_hash,
            x.event_hash,
          ]
            .map(field)
            .join(","),
        ),
      ].join("\r\n"),
    );
  }
}
