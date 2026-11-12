import "reflect-metadata";
import "dotenv/config";
import {
  Body,
  Controller,
  Get,
  Post,
  Param,
  Req,
  Res,
  Module,
  UseGuards,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
  ValidationPipe,
  Catch,
  ExceptionFilter,
  ArgumentsHost,
  HttpException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { Request, Response, json } from "express";
import helmet from "helmet";
import { static as serveStatic } from "express";
import { resolve } from "node:path";
import { WebController, ControlController } from "./control";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { Actor, pool, tx } from "./db";
import { Cash } from "./cash";
import { Security, Proof, audit, requireManager, dept } from "./security";
import { upload, download } from "./attachments";
import * as argon2 from "argon2";
const security = new Security(),
  cash = new Cash();
type Authed = Request & { actor: Actor };
const uuid = z.uuid();
const proof = z
  .object({
    challengeId: uuid,
    pin: z.string().regex(/^\d{6,12}$/),
    signature: z.string().min(40).max(2048).optional(),
    assertion: z.record(z.string(), z.unknown()).optional(),
    integrityToken: z.string().max(30000).optional(),
  })
  .strict();
const amount = z.string().regex(/^\d{1,16}$/);
const reason = z.string().trim().min(8).max(1000);
function parse<T>(schema: z.ZodType<T>, v: unknown): T {
  const r = schema.safeParse(v);
  if (!r.success) throw new BadRequestException("Invalid request");
  return r.data;
}
class Guard implements CanActivate {
  async canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest<Authed>();
    req.actor = await security.actor(
      req.headers.authorization?.replace(/^Bearer /, "") ?? "",
    );
    return true;
  }
}
@Controller("v1/auth")
class AuthController {
  @Post("challenge") async challenge(@Body() raw: any) {
    const b = parse(
      z
        .object({
          userId: uuid,
          deviceId: uuid,
          action: z.literal("LOGIN"),
          payload: z.object({ userId: uuid, deviceId: uuid }).strict(),
        })
        .strict(),
      raw,
    );
    if (b.userId !== b.payload.userId || b.deviceId !== b.payload.deviceId)
      throw new BadRequestException();
    return security.challenge(b.userId, b.deviceId, b.action, b.payload);
  }
  @Post("login") async login(@Body() raw: any) {
    const b = parse(
      z.object({ userId: uuid, deviceId: uuid, proof }).strict(),
      raw,
    );
    return security.login(b.userId, b.deviceId, b.proof);
  }
  @Post("refresh") async refresh(@Body() raw: any) {
    return security.refresh(
      parse(
        z.object({ refreshToken: z.string().min(40).max(100) }).strict(),
        raw,
      ).refreshToken,
    );
  }
}
@Controller("v1")
@UseGuards(Guard)
class ApiController {
  @Get("me") me(@Req() r: Authed) {
    return {
      id: r.actor.id,
      role: r.actor.role,
      departmentId: r.actor.department_id,
    };
  }
  @Post("challenge") challenge(@Req() r: Authed, @Body() raw: any) {
    const b = parse(
      z
        .object({
          action: z.enum([
            "COLLECT",
            "HANDOVER",
            "RECEIPT",
            "CANCEL",
            "REVIEW",
            "RESOLVE",
            "ADJUST",
            "EXPORT",
            "ADMIN",
            "ATTACHMENT",
          ]),
          payload: z.record(z.string(), z.unknown()),
        })
        .strict(),
      raw,
    );
    return security.challenge(
      r.actor.id,
      r.actor.device_id,
      b.action,
      b.payload,
    );
  }
  private async mutate(
    r: Authed,
    raw: any,
    schema: z.ZodType,
    action: string,
    run: (key: string, b: any) => Promise<any>,
    id?: string,
  ) {
    const b = parse(
      z.object({ key: uuid, data: schema, proof }).strict(),
      raw,
    ) as any;
    await security.verifyProof(
      r.actor,
      action,
      id ? { id, ...b.data } : b.data,
      b.proof,
    );
    return run(b.key, b.data);
  }
  @Post("collections") collect(@Req() r: Authed, @Body() b: any) {
    return this.mutate(
      r,
      b,
      z
        .object({ customerName: z.string().trim().min(1).max(120), amount })
        .strict(),
      "COLLECT",
      (key, data) => cash.collect(r.actor, key, data),
    );
  }
  @Post("handovers") initiate(@Req() r: Authed, @Body() b: any) {
    return this.mutate(
      r,
      b,
      z
        .object({
          receiverId: uuid,
          allocations: z
            .array(z.object({ collectionId: uuid, amount }).strict())
            .min(1)
            .max(100),
        })
        .strict(),
      "HANDOVER",
      (key, data) => cash.initiate(r.actor, key, data),
    );
  }
  @Post("handovers/:id/receipt") receipt(
    @Req() r: Authed,
    @Param("id") id: string,
    @Body() b: any,
  ) {
    parse(uuid, id);
    return this.mutate(
      r,
      b,
      z
        .object({
          actual: amount,
          decision: z.enum(["ACCEPT", "DISPUTE", "REJECT"]),
          reason: reason.optional(),
        })
        .strict(),
      "RECEIPT",
      (key, data) => cash.receipt(r.actor, key, id, data),
      id,
    );
  }
  @Post("handovers/:id/cancel") cancel(
    @Req() r: Authed,
    @Param("id") id: string,
    @Body() b: any,
  ) {
    parse(uuid, id);
    return this.mutate(
      r,
      b,
      z.object({}).strict(),
      "CANCEL",
      (key) => cash.cancel(r.actor, key, id),
      id,
    );
  }
  @Post("collections/:id/review") review(
    @Req() r: Authed,
    @Param("id") id: string,
    @Body() b: any,
  ) {
    parse(uuid, id);
    return this.mutate(
      r,
      b,
      z
        .object({
          decision: z.enum(["APPROVE", "REJECT", "DISCREPANCY"]),
          reason: reason.optional(),
        })
        .strict(),
      "REVIEW",
      (key, data) => cash.review(r.actor, key, id, data),
      id,
    );
  }
  @Post("discrepancies/:id/resolve") resolve(
    @Req() r: Authed,
    @Param("id") id: string,
    @Body() b: any,
  ) {
    parse(uuid, id);
    return this.mutate(
      r,
      b,
      z
        .object({
          resolution: z.enum([
            "RECOUNT_MATCHED",
            "RETURN_CONFIRMED",
            "REVIEW_CLEARED",
          ]),
          reason,
        })
        .strict(),
      "RESOLVE",
      (key, data) => cash.resolve(r.actor, key, id, data),
      id,
    );
  }
  @Post("collections/:id/adjustments") adjust(
    @Req() r: Authed,
    @Param("id") id: string,
    @Body() b: any,
  ) {
    parse(uuid, id);
    return this.mutate(
      r,
      b,
      z.object({ delta: z.string().max(17), reason }).strict(),
      "ADJUST",
      (key, data) => cash.adjust(r.actor, key, id, data),
      id,
    );
  }
  @Get("tasks") tasks(@Req() r: Authed) {
    return cash.tasks(r.actor);
  }
  @Get("status/:id") status(@Req() r: Authed, @Param("id") id: string) {
    return cash.status(r.actor, parse(uuid, id));
  }
  @Get("departments/:id/collections") records(
    @Req() r: Authed,
    @Param("id") id: string,
  ) {
    return cash.records(r.actor, parse(uuid, id));
  }
  @Get("collections/:id/chain") chain(
    @Req() r: Authed,
    @Param("id") id: string,
  ) {
    return cash.chain(r.actor, parse(uuid, id));
  }
  @Get("departments/:id/dashboard") dashboard(
    @Req() r: Authed,
    @Param("id") id: string,
  ) {
    return cash.dashboard(r.actor, parse(uuid, id));
  }
  @Get("departments/:id/audit") auditLog(
    @Req() r: Authed,
    @Param("id") id: string,
  ) {
    return cash
      .auditLog(r.actor, parse(uuid, id))
      .then((events) => ({ events }));
  }
  @Post("departments/:id/export") async export(
    @Req() r: Authed,
    @Param("id") id: string,
    @Body() raw: any,
    @Res() res: Response,
  ) {
    requireManager(r.actor);
    parse(uuid, id);
    const b = parse(z.object({ proof }).strict(), raw);
    await security.verifyProof(
      r.actor,
      "EXPORT",
      { departmentId: id },
      b.proof,
    );
    const records = await cash.records(r.actor, id, 100001);
    if (records.collections.length > 100000)
      throw new BadRequestException(
        "Export exceeds 100,000 rows; use a narrower reporting period.",
      );
    await tx(r.actor, (c) =>
      audit(c, r.actor, id, "REPORT_EXPORTED", null, {
        count: records.collections.length,
      }),
    );
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="cashtrack.csv"',
    );
    res.send(
      "reference,amount_paise,state\n" +
        records.collections
          .map((x) => `${x.id},${x.amount},${x.state}`)
          .join("\n"),
    );
  }
  @Post("collections/:id/attachments") async upload(
    @Req() r: Authed,
    @Param("id") id: string,
    @Body() raw: any,
  ) {
    requireManager(r.actor);
    parse(uuid, id);
    const b = parse(
      z.object({ data: z.string().max(1400000), proof }).strict(),
      raw,
    );
    await security.verifyProof(
      r.actor,
      "ATTACHMENT",
      {
        id,
        sha256: (await import("./security")).hash(
          Buffer.from(b.data, "base64").toString("base64"),
        ),
      },
      b.proof,
    );
    return upload(r.actor, id, b.data);
  }
  @Get("attachments/:id") async attachment(
    @Req() r: Authed,
    @Param("id") id: string,
    @Res() res: Response,
  ) {
    const at = await cash.attachment(r.actor, parse(uuid, id));
    const bytes = await download(at);
    res.setHeader("Content-Type", at.content_type);
    res.setHeader("Content-Disposition", 'attachment; filename="receipt"');
    res.send(bytes);
  }
  @Post("logout") async logout(@Req() r: Authed) {
    await pool.query("UPDATE sessions SET revoked=true WHERE id=$1", [
      r.actor.session_id,
    ]);
    return { status: "REVOKED" };
  }
  @Get("admin/departments") async departments(@Req() r: Authed) {
    if (r.actor.role !== "SUPER_ADMIN") throw new ForbiddenException();
    return {
      departments: (await pool.query("SELECT * FROM departments ORDER BY name"))
        .rows,
    };
  }
  @Get("admin/users") async users(@Req() r: Authed) {
    if (r.actor.role !== "SUPER_ADMIN") throw new ForbiddenException();
    return {
      users: (
        await pool.query(
          "SELECT u.id,u.name,u.email,u.active,r.role,r.department_id FROM users u JOIN role_assignments r ON r.user_id=u.id ORDER BY u.name LIMIT 1000",
        )
      ).rows,
    };
  }
  @Post("admin") async admin(@Req() r: Authed, @Body() raw: any) {
    if (r.actor.role !== "SUPER_ADMIN") throw new ForbiddenException();
    const b = parse(
      z
        .object({
          data: z.discriminatedUnion("operation", [
            z
              .object({
                operation: z.literal("DEPARTMENT"),
                id: uuid,
                name: z.string().min(1).max(100),
                dailyTarget: amount,
                maxHops: z.number().int().positive().nullable(),
                overdueMinutes: z.number().int().min(1).max(10080),
                gamification: z.boolean(),
              })
              .strict(),
            z
              .object({
                operation: z.literal("USER"),
                id: uuid,
                email: z.email(),
                name: z.string().min(1).max(100),
                pin: z.string().regex(/^\d{6,12}$/),
                role: z.enum(["HOD", "COLLECTOR", "SUPER_ADMIN"]),
                departmentId: uuid.nullable(),
              })
              .strict(),
            z.object({ operation: z.literal("REVOKE"), userId: uuid }).strict(),
          ]),
          proof,
        })
        .strict(),
      raw,
    );
    await security.verifyProof(r.actor, "ADMIN", b.data, b.proof);
    return tx(r.actor, async (c) => {
      const d = b.data;
      if (d.operation === "DEPARTMENT") {
        await c.query(
          "INSERT INTO departments(id,name,daily_target,max_hops,overdue_minutes,gamification) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,daily_target=EXCLUDED.daily_target,max_hops=EXCLUDED.max_hops,overdue_minutes=EXCLUDED.overdue_minutes,gamification=EXCLUDED.gamification",
          [
            d.id,
            d.name,
            d.dailyTarget,
            d.maxHops,
            d.overdueMinutes,
            d.gamification,
          ],
        );
        await audit(c, r.actor, d.id, "DEPARTMENT_CONFIGURED", null, { ...d });
      } else if (d.operation === "USER") {
        if (
          d.departmentId &&
          !(
            await c.query("SELECT 1 FROM departments WHERE id=$1 AND active", [
              d.departmentId,
            ])
          ).rowCount
        )
          throw new ConflictException("Choose an active department");
        if ((d.role === "SUPER_ADMIN") !== (d.departmentId === null))
          throw new BadRequestException();
        await c.query(
          "INSERT INTO users(id,email,name,pin_hash) VALUES($1,$2,$3,$4)",
          [
            d.id,
            d.email,
            d.name,
            await argon2.hash(d.pin, {
              type: argon2.argon2id,
              memoryCost: 65536,
              timeCost: 3,
              parallelism: 1,
            }),
          ],
        );
        await c.query("INSERT INTO role_assignments VALUES($1,$2,$3)", [
          d.id,
          d.departmentId,
          d.role,
        ]);
        await audit(c, r.actor, d.departmentId, "USER_CREATED", null, {
          id: d.id,
          role: d.role,
        });
      } else {
        await c.query("SELECT pg_advisory_xact_lock(878878)");
        const target = (
          await c.query(
            "SELECT u.active,r.role FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE u.id=$1 FOR UPDATE OF u,r",
            [d.userId],
          )
        ).rows[0];
        if (!target) throw new NotFoundException();
        if (
          target.role === "SUPER_ADMIN" &&
          target.active &&
          !(
            await c.query(
              "SELECT 1 FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE u.active AND r.role='SUPER_ADMIN' AND u.id<>$1",
              [d.userId],
            )
          ).rowCount
        )
          throw new ConflictException("Keep at least one active Super Admin");
        await c.query(
          "UPDATE users SET session_version=session_version+1,active=false WHERE id=$1",
          [d.userId],
        );
        await c.query("UPDATE sessions SET revoked=true WHERE user_id=$1", [
          d.userId,
        ]);
        await audit(c, r.actor, null, "USER_REVOKED", null, { id: d.userId });
      }
      return { status: "DONE" };
    });
  }
}
@Catch()
class Errors implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();
    const status = error instanceof HttpException ? error.getStatus() : 500;
    res.status(status).json({
      statusCode: status,
      message:
        status === 500
          ? "Request could not be completed"
          : error instanceof HttpException
            ? error.message
            : "Request rejected",
    });
  }
}
@Module({
  controllers: [
    AuthController,
    ApiController,
    WebController,
    ControlController,
  ],
})
class AppModule {}
export async function start() {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 48)
    throw Error("JWT_SECRET must be at least 48 random characters");
  const app = await NestFactory.create(AppModule, {
    logger: ["error", "warn"],
    bodyParser: false,
  });
  app.useGlobalFilters(new Errors());
  app.use(helmet());
  app.use(json({ limit: "2mb" }));
  // Bounded per-IP limiter. Use ingress distributed rate limits for multiple replicas.
  const windows = new Map<string, { n: number; until: number }>();
  app.use((req: Request, res: Response, next: any) => {
    const now = Date.now(),
      ip = req.socket.remoteAddress ?? "unknown";
    if (windows.size > 10000)
      for (const [k, v] of windows) if (v.until < now) windows.delete(k);
    let w = windows.get(ip);
    if (!w || w.until < now) {
      w = { n: 0, until: now + 60000 };
      windows.set(ip, w);
    }
    if (++w.n > 120) {
      res.setHeader("Retry-After", "60");
      return res.status(429).end();
    }
    res.setHeader("Cache-Control", "no-store");
    next();
  });
  app.use(
    "/control",
    serveStatic(resolve(__dirname, "../public"), {
      index: "index.html",
      etag: false,
      maxAge: 0,
    }),
  );
  await app.listen(Number(process.env.PORT ?? 3000), "0.0.0.0");
  return app;
}
if (require.main === module) void start();
