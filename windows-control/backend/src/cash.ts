import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { PoolClient } from "pg";
import { Actor, tx } from "./db";
import {
  amount,
  audit,
  canonical,
  dept,
  hash,
  requireManager,
} from "./security";
const fail = (s: string): never => {
  throw new ConflictException(s);
};
export class Cash {
  async once(
    a: Actor,
    key: string,
    action: string,
    body: any,
    fn: (c: PoolClient) => Promise<any>,
  ) {
    return tx(a, async (c) => {
      // Serialize permission changes against financial commits. A request must
      // not commit using a role/department that changed after its HTTP guard.
      const current = (
        await c.query(
          "SELECT u.active,r.role,r.department_id FROM users u JOIN role_assignments r ON r.user_id=u.id WHERE u.id=$1 FOR SHARE OF u,r",
          [a.id],
        )
      ).rows[0];
      if (
        !current?.active ||
        current.role !== a.role ||
        current.department_id !== a.department_id
      )
        throw new ForbiddenException(
          "Account permissions changed; authenticate again",
        );
      const h = hash(canonical({ action, body }));
      await c.query(
        "INSERT INTO idempotency_records(user_id,key,department_id,request_hash) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
        [a.id, key, a.department_id, h],
      );
      const r = (
        await c.query(
          "SELECT * FROM idempotency_records WHERE user_id=$1 AND key=$2 FOR UPDATE",
          [a.id, key],
        )
      ).rows[0];
      if (r.request_hash !== h)
        throw new ConflictException(
          "Idempotency key reused with different request",
        );
      if (r.response) return r.response;
      const result = await fn(c);
      await c.query(
        "UPDATE idempotency_records SET response=$1 WHERE user_id=$2 AND key=$3",
        [result, a.id, key],
      );
      return result;
    });
  }
  async collect(
    a: Actor,
    key: string,
    b: { customerName: string; amount: string },
  ) {
    if (a.role !== "COLLECTOR") throw new ForbiddenException();
    const n = amount(b.amount);
    return this.once(a, key, "COLLECT", b, async (c) => {
      const customer = randomUUID(),
        id = randomUUID();
      await c.query(
        "INSERT INTO customers(id,department_id,name) VALUES($1,$2,$3)",
        [customer, a.department_id, b.customerName],
      );
      await c.query(
        `INSERT INTO cash_collections(id,department_id,customer_id,created_by,amount,state,receipt_id) VALUES($1,$2,$3,$4,$5,'IN_CUSTODY',$6)`,
        [id, a.department_id, customer, a.id, n.toString(), randomUUID()],
      );
      await c.query(
        "INSERT INTO custody_positions(collection_id,department_id,holder_id,amount) VALUES($1,$2,$3,$4)",
        [id, a.department_id, a.id, n.toString()],
      );
      await c.query(
        "INSERT INTO custody_ledger_entries(id,department_id,collection_id,to_user,amount) VALUES($1,$2,$3,$4,$5)",
        [randomUUID(), a.department_id, id, a.id, n.toString()],
      );
      await c.query(
        "INSERT INTO hod_approvals(collection_id,department_id) VALUES($1,$2)",
        [id, a.department_id],
      );
      await audit(c, a, a.department_id, "COLLECTION_CREATED", null, {
        reference: id,
        amount: b.amount,
      });
      return { reference: id, status: "IN_CUSTODY" };
    });
  }
  async initiate(
    a: Actor,
    key: string,
    b: {
      receiverId: string;
      allocations: { collectionId: string; amount: string }[];
    },
  ) {
    if (a.role !== "COLLECTOR" || a.id === b.receiverId)
      throw new ForbiddenException();
    if (
      new Set(b.allocations.map((x) => x.collectionId)).size !==
      b.allocations.length
    )
      throw new BadRequestException("Duplicate allocations");
    const total = b.allocations.reduce((s, x) => s + amount(x.amount), 0n);
    amount(total.toString());
    return this.once(a, key, "HANDOVER", b, async (c) => {
      const receiver = (
        await c.query(
          `SELECT r.* FROM role_assignments r JOIN users u ON u.id=r.user_id WHERE u.id=$1 AND u.active FOR SHARE OF u,r`,
          [b.receiverId],
        )
      ).rows[0];
      if (
        !receiver ||
        receiver.department_id !== a.department_id ||
        !["HOD", "COLLECTOR"].includes(receiver.role)
      )
        throw new ForbiddenException();
      const policy = (
        await c.query("SELECT max_hops FROM departments WHERE id=$1", [
          a.department_id,
        ])
      ).rows[0];
      const id = randomUUID();
      await c.query(
        `INSERT INTO handovers(id,department_id,sender_id,receiver_id,expected,state) VALUES($1,$2,$3,$4,$5,'PENDING_RECEIPT')`,
        [id, a.department_id, a.id, b.receiverId, total.toString()],
      );
      for (const al of [...b.allocations].sort((x, y) =>
        x.collectionId.localeCompare(y.collectionId),
      )) {
        const col = (
          await c.query(
            "SELECT * FROM cash_collections WHERE id=$1 FOR UPDATE",
            [al.collectionId],
          )
        ).rows[0];
        if (
          !col ||
          col.department_id !== a.department_id ||
          col.state === "APPROVED"
        )
          throw new NotFoundException();
        const p = (
          await c.query(
            "SELECT * FROM custody_positions WHERE collection_id=$1 AND holder_id=$2 FOR UPDATE",
            [al.collectionId, a.id],
          )
        ).rows[0];
        if (
          !p ||
          BigInt(p.amount) - BigInt(p.reserved) - BigInt(p.blocked) <
            amount(al.amount)
        )
          fail("Insufficient available custody");
        if (
          receiver.role === "COLLECTOR" &&
          policy.max_hops !== null &&
          p.hops >= policy.max_hops
        )
          fail("Configured collector hop limit reached");
        await c.query(
          "UPDATE custody_positions SET reserved=reserved+$1 WHERE collection_id=$2 AND holder_id=$3",
          [al.amount, al.collectionId, a.id],
        );
        await c.query("INSERT INTO handover_allocations VALUES($1,$2,$3,$4)", [
          id,
          al.collectionId,
          a.department_id,
          al.amount,
        ]);
      }
      await audit(c, a, a.department_id, "HANDOVER_RESERVED", null, {
        reference: id,
        ...b,
      });
      return { reference: id, status: "PENDING_RECEIPT" };
    });
  }
  async receipt(
    a: Actor,
    key: string,
    id: string,
    b: {
      actual: string;
      reason?: string;
      decision: "ACCEPT" | "DISPUTE" | "REJECT";
    },
  ) {
    amount(b.actual, true);
    return this.once(a, key, "RECEIPT", { id, ...b }, async (c) => {
      const h = await this.handover(c, a, id);
      if (h.receiver_id !== a.id || h.sender_id === a.id)
        throw new ForbiddenException();
      if (h.state !== "PENDING_RECEIPT") fail("Handover already processed");
      if (b.decision !== "ACCEPT" && !b.reason)
        throw new BadRequestException("Reason required");
      const als = (
        await c.query(
          "SELECT * FROM handover_allocations WHERE handover_id=$1 ORDER BY collection_id",
          [id],
        )
      ).rows;
      // Lock every source collection in the same deterministic order used by initiation/approval.
      for (const al of als)
        await c.query(
          "SELECT id FROM cash_collections WHERE id=$1 FOR UPDATE",
          [al.collection_id],
        );
      if (b.decision === "REJECT") {
        for (const al of als)
          await c.query(
            "UPDATE custody_positions SET reserved=reserved-$1 WHERE collection_id=$2 AND holder_id=$3",
            [al.amount, al.collection_id, h.sender_id],
          );
        await c.query("UPDATE handovers SET state='REJECTED' WHERE id=$1", [
          id,
        ]);
        await audit(
          c,
          a,
          h.department_id,
          "HANDOVER_REJECTED",
          { state: h.state },
          { reference: id },
          b.reason,
        );
        return { reference: id, status: "REJECTED" };
      }
      await c.query(
        "INSERT INTO receipt_confirmations VALUES($1,$2,$3,$4,$5,now())",
        [randomUUID(), id, h.department_id, a.id, b.actual],
      );
      const matched =
        b.decision === "ACCEPT" && BigInt(b.actual) === BigInt(h.expected);
      for (const al of als) {
        if (matched) await this.move(c, h, al);
        else
          await c.query(
            "UPDATE custody_positions SET reserved=reserved-$1,blocked=blocked+$1 WHERE collection_id=$2 AND holder_id=$3",
            [al.amount, al.collection_id, h.sender_id],
          );
      }
      const status = matched ? "RECEIVED" : "DISPUTED";
      await c.query("UPDATE handovers SET state=$1 WHERE id=$2", [status, id]);
      if (!matched) {
        await c.query(
          "INSERT INTO discrepancies(id,department_id,handover_id,expected,actual,reason) VALUES($1,$2,$3,$4,$5,$6)",
          [
            randomUUID(),
            h.department_id,
            id,
            h.expected,
            b.actual,
            b.reason ?? "Count mismatch",
          ],
        );
        for (const al of als)
          await c.query(
            "UPDATE hod_approvals SET state='DISCREPANCY_OPEN',updated_at=now() WHERE collection_id=$1",
            [al.collection_id],
          );
      }
      await audit(
        c,
        a,
        h.department_id,
        matched ? "CUSTODY_TRANSFERRED" : "DISCREPANCY_OPEN",
        null,
        { reference: id, actual: b.actual, status },
        b.reason,
      );
      return { reference: id, status };
    });
  }
  private async handover(c: PoolClient, a: Actor, id: string) {
    const h = (
      await c.query("SELECT * FROM handovers WHERE id=$1 FOR UPDATE", [id])
    ).rows[0];
    if (!h) throw new NotFoundException();
    dept(a, h.department_id);
    return h;
  }
  private async move(c: PoolClient, h: any, al: any, blocked = false) {
    const p = (
      await c.query(
        "SELECT hops FROM custody_positions WHERE collection_id=$1 AND holder_id=$2 FOR UPDATE",
        [al.collection_id, h.sender_id],
      )
    ).rows[0];
    await c.query(
      `UPDATE custody_positions SET amount=amount-$1,${blocked ? "blocked" : "reserved"}=${blocked ? "blocked" : "reserved"}-$1 WHERE collection_id=$2 AND holder_id=$3`,
      [al.amount, al.collection_id, h.sender_id],
    );
    await c.query(
      "INSERT INTO custody_positions(collection_id,department_id,holder_id,amount,hops) VALUES($1,$2,$3,$4,$5) ON CONFLICT(collection_id,holder_id) DO UPDATE SET amount=custody_positions.amount+EXCLUDED.amount,hops=GREATEST(custody_positions.hops,EXCLUDED.hops)",
      [al.collection_id, h.department_id, h.receiver_id, al.amount, p.hops + 1],
    );
    await c.query(
      "INSERT INTO custody_ledger_entries VALUES($1,$2,$3,$4,$5,$6,$7,now())",
      [
        randomUUID(),
        h.department_id,
        al.collection_id,
        h.id,
        h.sender_id,
        h.receiver_id,
        al.amount,
      ],
    );
    await c.query(
      `UPDATE cash_collections SET state=CASE WHEN NOT EXISTS(SELECT 1 FROM custody_positions p JOIN role_assignments r ON r.user_id=p.holder_id WHERE p.collection_id=$1 AND p.amount>0 AND r.role<>'HOD') THEN 'HANDED_TO_HOD' ELSE 'IN_CUSTODY' END WHERE id=$1`,
      [al.collection_id],
    );
  }
  async cancel(a: Actor, key: string, id: string) {
    return this.once(a, key, "CANCEL", { id }, async (c) => {
      const h = await this.handover(c, a, id);
      if (h.sender_id !== a.id) throw new ForbiddenException();
      if (h.state !== "PENDING_RECEIPT")
        fail("Only unreceived handovers can be cancelled");
      const als = (
        await c.query(
          "SELECT * FROM handover_allocations WHERE handover_id=$1 ORDER BY collection_id",
          [id],
        )
      ).rows;
      for (const al of als) {
        await c.query(
          "SELECT id FROM cash_collections WHERE id=$1 FOR UPDATE",
          [al.collection_id],
        );
        await c.query(
          "UPDATE custody_positions SET reserved=reserved-$1 WHERE collection_id=$2 AND holder_id=$3",
          [al.amount, al.collection_id, a.id],
        );
      }
      await c.query("UPDATE handovers SET state='CANCELLED' WHERE id=$1", [id]);
      await audit(c, a, h.department_id, "HANDOVER_CANCELLED", null, {
        reference: id,
      });
      return { reference: id, status: "CANCELLED" };
    });
  }
  async review(
    a: Actor,
    key: string,
    id: string,
    b: { decision: "APPROVE" | "REJECT" | "DISCREPANCY"; reason?: string },
  ) {
    if (a.role !== "HOD")
      throw new ForbiddenException("Final approval is HOD only");
    if (b.decision !== "APPROVE" && !b.reason)
      throw new BadRequestException("Reason required");
    return this.once(a, key, "REVIEW", { id, ...b }, async (c) => {
      const col = (
        await c.query("SELECT * FROM cash_collections WHERE id=$1 FOR UPDATE", [
          id,
        ])
      ).rows[0];
      if (!col) throw new NotFoundException();
      dept(a, col.department_id);
      if (col.created_by === a.id || col.state === "APPROVED")
        fail("Collection cannot be reviewed");
      await c.query(
        "UPDATE hod_approvals SET state='UNDER_REVIEW',hod_id=$2,updated_at=now() WHERE collection_id=$1",
        [id, a.id],
      );
      if (b.decision === "APPROVE") {
        const positions = (
          await c.query(
            "SELECT * FROM custody_positions WHERE collection_id=$1 FOR UPDATE",
            [id],
          )
        ).rows;
        const owned = positions
          .filter((p) => p.holder_id === a.id)
          .reduce((s, p) => s + BigInt(p.amount), 0n);
        const issues = (
          await c.query(
            `SELECT 1 FROM discrepancies d LEFT JOIN handover_allocations al ON al.handover_id=d.handover_id WHERE d.state='OPEN' AND (d.collection_id=$1 OR al.collection_id=$1) LIMIT 1`,
            [id],
          )
        ).rowCount;
        if (
          col.state !== "HANDED_TO_HOD" ||
          owned !== BigInt(col.amount) ||
          positions.some(
            (p) => BigInt(p.reserved) > 0n || BigInt(p.blocked) > 0n,
          ) ||
          issues
        )
          fail("Confirmed, fully reconciled HOD custody required");
        await c.query(
          "UPDATE cash_collections SET state='APPROVED',approved_at=now() WHERE id=$1",
          [id],
        );
      }
      const state =
        b.decision === "APPROVE"
          ? "APPROVED"
          : b.decision === "REJECT"
            ? "REJECTED"
            : "DISCREPANCY_OPEN";
      await c.query(
        "UPDATE hod_approvals SET state=$1,reason=$2,updated_at=now() WHERE collection_id=$3",
        [state, b.reason ?? null, id],
      );
      if (b.decision === "DISCREPANCY")
        await c.query(
          "INSERT INTO discrepancies(id,department_id,collection_id,expected,actual,reason) VALUES($1,$2,$3,$4,$4,$5)",
          [randomUUID(), col.department_id, id, col.amount, b.reason],
        );
      await audit(
        c,
        a,
        col.department_id,
        "HOD_" + state,
        { state: col.state },
        { reference: id, status: state },
        b.reason,
      );
      return { reference: id, status: state };
    });
  }
  async resolve(
    a: Actor,
    key: string,
    id: string,
    b: {
      resolution: "RECOUNT_MATCHED" | "RETURN_CONFIRMED" | "REVIEW_CLEARED";
      reason: string;
    },
  ) {
    if (a.role !== "HOD") throw new ForbiddenException();
    return this.once(a, key, "RESOLVE", { id, ...b }, async (c) => {
      const d = (
        await c.query("SELECT * FROM discrepancies WHERE id=$1 FOR UPDATE", [
          id,
        ])
      ).rows[0];
      if (!d) throw new NotFoundException();
      dept(a, d.department_id);
      if (d.state !== "OPEN") fail("Already resolved");
      let ids: string[] = [];
      if (d.handover_id) {
        if (b.resolution === "REVIEW_CLEARED")
          fail("Physical custody decision required");
        const h = await this.handover(c, a, d.handover_id);
        const als = (
          await c.query(
            "SELECT * FROM handover_allocations WHERE handover_id=$1 ORDER BY collection_id",
            [h.id],
          )
        ).rows;
        ids = als.map((al) => al.collection_id);
        for (const al of als) {
          await c.query(
            "SELECT id FROM cash_collections WHERE id=$1 FOR UPDATE",
            [al.collection_id],
          );
          if (b.resolution === "RECOUNT_MATCHED")
            await this.move(c, h, al, true);
          else
            await c.query(
              "UPDATE custody_positions SET blocked=blocked-$1 WHERE collection_id=$2 AND holder_id=$3",
              [al.amount, al.collection_id, h.sender_id],
            );
        }
        await c.query("UPDATE handovers SET state=$1 WHERE id=$2", [
          b.resolution === "RECOUNT_MATCHED" ? "RECEIVED" : "REJECTED",
          h.id,
        ]);
      } else {
        if (b.resolution !== "REVIEW_CLEARED") fail("Use review clearance");
        ids = [d.collection_id];
      }
      await c.query(
        "UPDATE discrepancies SET state='RESOLVED',resolution=$1,resolved_by=$2 WHERE id=$3",
        [b.resolution + ": " + b.reason, a.id, id],
      );
      for (const cid of ids)
        await c.query(
          "UPDATE hod_approvals SET state='PENDING_HOD',updated_at=now() WHERE collection_id=$1",
          [cid],
        );
      await audit(
        c,
        a,
        d.department_id,
        "DISCREPANCY_RESOLVED",
        d,
        { reference: id, ...b },
        b.reason,
      );
      return { reference: id, status: "RESOLVED" };
    });
  }
  async adjust(
    a: Actor,
    key: string,
    id: string,
    b: { delta: string; reason: string },
  ) {
    requireManager(a);
    if (
      !/^-?[1-9]\d{0,15}$/.test(b.delta) ||
      BigInt(b.delta) > 9000000000000000n ||
      BigInt(b.delta) < -9000000000000000n
    )
      throw new BadRequestException();
    return this.once(a, key, "ADJUST", { id, ...b }, async (c) => {
      const col = (
        await c.query("SELECT * FROM cash_collections WHERE id=$1 FOR UPDATE", [
          id,
        ])
      ).rows[0];
      if (!col) throw new NotFoundException();
      dept(a, col.department_id);
      if (col.state !== "APPROVED")
        fail("Use discrepancy workflow before approval");
      const ref = randomUUID();
      await c.query("INSERT INTO adjustments VALUES($1,$2,$3,$4,$5,$6,now())", [
        ref,
        col.department_id,
        id,
        b.delta,
        b.reason,
        a.id,
      ]);
      await audit(
        c,
        a,
        col.department_id,
        "ADJUSTMENT_POSTED",
        null,
        { reference: ref, collectionId: id, delta: b.delta },
        b.reason,
      );
      return { reference: ref, status: "POSTED" };
    });
  }
  async tasks(a: Actor) {
    return tx(a, async (c) => ({
      tasks: (
        await c.query(
          `SELECT id reference,state status FROM handovers WHERE receiver_id=$1 AND state='PENDING_RECEIPT' ORDER BY created_at LIMIT 100`,
          [a.id],
        )
      ).rows,
    }));
  }
  async status(a: Actor, id: string) {
    return tx(a, async (c) => {
      const h = (
        await c.query(
          "SELECT id reference,state status FROM handovers WHERE id=$1 AND (sender_id=$2 OR receiver_id=$2)",
          [id, a.id],
        )
      ).rows[0];
      const col =
        h ??
        (
          await c.query(
            "SELECT id reference,state status FROM cash_collections WHERE id=$1 AND created_by=$2",
            [id, a.id],
          )
        ).rows[0];
      if (!col) throw new NotFoundException();
      return col;
    });
  }
  async records(a: Actor, department: string, limit = 500) {
    requireManager(a);
    dept(a, department);
    return tx(a, async (c) => ({
      collections: (
        await c.query(
          `SELECT c.*,u.name collector,cu.name customer,ap.state approval_status FROM cash_collections c JOIN users u ON u.id=c.created_by JOIN customers cu ON cu.id=c.customer_id JOIN hod_approvals ap ON ap.collection_id=c.id WHERE c.department_id=$1 ORDER BY c.created_at DESC LIMIT $2`,
          [department, limit],
        )
      ).rows,
    }));
  }
  async chain(a: Actor, id: string) {
    requireManager(a);
    return tx(a, async (c) => {
      const col = (
        await c.query("SELECT * FROM cash_collections WHERE id=$1", [id])
      ).rows[0];
      if (!col) throw new NotFoundException();
      dept(a, col.department_id);
      return {
        collection: col,
        ledger: (
          await c.query(
            "SELECT * FROM custody_ledger_entries WHERE collection_id=$1 ORDER BY created_at",
            [id],
          )
        ).rows,
        positions: (
          await c.query(
            "SELECT * FROM custody_positions WHERE collection_id=$1",
            [id],
          )
        ).rows,
        handovers: (
          await c.query(
            "SELECT h.*,rc.actual FROM handovers h JOIN handover_allocations al ON al.handover_id=h.id LEFT JOIN receipt_confirmations rc ON rc.handover_id=h.id WHERE al.collection_id=$1",
            [id],
          )
        ).rows,
        discrepancies: (
          await c.query(
            "SELECT DISTINCT d.* FROM discrepancies d LEFT JOIN handover_allocations al ON al.handover_id=d.handover_id WHERE d.collection_id=$1 OR al.collection_id=$1",
            [id],
          )
        ).rows,
      };
    });
  }
  async dashboard(a: Actor, department: string) {
    requireManager(a);
    dept(a, department);
    return tx(a, async (c) => {
      const totals = (
        await c.query(
          `SELECT COALESCE(sum(amount),0)::text collected,COALESCE(sum(amount) FILTER(WHERE state='APPROVED'),0)::text approved FROM cash_collections WHERE department_id=$1 AND created_at>=(now() AT TIME ZONE 'Asia/Kolkata')::date AT TIME ZONE 'Asia/Kolkata'`,
          [department],
        )
      ).rows[0];
      const held = (
        await c.query(
          `SELECT COALESCE(sum(p.amount),0)::text held FROM custody_positions p JOIN role_assignments r ON r.user_id=p.holder_id WHERE p.department_id=$1 AND r.role='COLLECTOR'`,
          [department],
        )
      ).rows[0];
      const policy = (
        await c.query("SELECT * FROM departments WHERE id=$1", [department])
      ).rows[0];
      const leaderboard = (
        await c.query(
          `SELECT u.name,COALESCE(sum(l.amount),0)::text amount FROM custody_ledger_entries l JOIN role_assignments r ON r.user_id=l.to_user JOIN users u ON u.id=l.from_user WHERE l.department_id=$1 AND r.role='HOD' AND l.created_at>=(now() AT TIME ZONE 'Asia/Kolkata')::date AT TIME ZONE 'Asia/Kolkata' GROUP BY u.id ORDER BY sum(l.amount) DESC LIMIT 5`,
          [department],
        )
      ).rows;
      return {
        ...totals,
        ...held,
        target: policy?.daily_target,
        leaderboard,
        discrepancies: (
          await c.query(
            "SELECT * FROM discrepancies WHERE department_id=$1 AND state='OPEN'",
            [department],
          )
        ).rows,
        overdue: (
          await c.query(
            "SELECT count(*)::int n FROM custody_positions p JOIN cash_collections cc ON cc.id=p.collection_id JOIN role_assignments r ON r.user_id=p.holder_id WHERE p.department_id=$1 AND p.amount>0 AND r.role='COLLECTOR' AND cc.created_at<now()-make_interval(mins=>$2)",
            [department, policy?.overdue_minutes ?? 120],
          )
        ).rows[0].n,
        trend: (
          await c.query(
            "SELECT (created_at AT TIME ZONE 'Asia/Kolkata')::date AS day,sum(amount)::text amount FROM cash_collections WHERE department_id=$1 AND created_at>now()-interval '30 days' GROUP BY 1 ORDER BY 1",
            [department],
          )
        ).rows,
      };
    });
  }
  async auditLog(a: Actor, department: string) {
    requireManager(a);
    dept(a, department);
    return tx(
      a,
      async (c) =>
        (
          await c.query(
            "SELECT * FROM audit_events WHERE department_id=$1 ORDER BY seq DESC LIMIT 500",
            [department],
          )
        ).rows,
    );
  }
  async attachment(a: Actor, id: string) {
    requireManager(a);
    return tx(a, async (c) => {
      const at = (await c.query("SELECT * FROM attachments WHERE id=$1", [id]))
        .rows[0];
      if (!at) throw new NotFoundException();
      dept(a, at.department_id);
      return at;
    });
  }
}
