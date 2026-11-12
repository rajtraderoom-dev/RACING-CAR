import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} from "@aws-sdk/client-s3";
import { BadRequestException, NotFoundException } from "@nestjs/common";
import { randomUUID, createHash } from "node:crypto";
import { Actor, tx } from "./db";
import { requireManager, dept, audit } from "./security";
const s3 = () => new S3Client({ region: process.env.AWS_REGION });
export async function upload(a: Actor, id: string, data: string) {
  requireManager(a);
  if (!process.env.ATTACHMENT_BUCKET || !process.env.ATTACHMENT_KMS_KEY)
    throw new BadRequestException("Encrypted object storage is not configured");
  const bytes = Buffer.from(data, "base64");
  if (bytes.length > 1000000 || bytes.length < 8)
    throw new BadRequestException("Photo size invalid");
  let type = "";
  if (bytes.subarray(0, 3).equals(Buffer.from([255, 216, 255])))
    type = "image/jpeg";
  else if (
    bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
  )
    type = "image/png";
  else throw new BadRequestException("Only JPEG or PNG");
  const key = randomUUID();
  return tx(a, async (c) => {
    const col = (
      await c.query("SELECT * FROM cash_collections WHERE id=$1 FOR UPDATE", [
        id,
      ])
    ).rows[0];
    if (!col) throw new NotFoundException();
    dept(a, col.department_id);
    if (col.state === "APPROVED")
      throw new BadRequestException("Approved attachments are immutable");
    const object = `${col.department_id}/${id}/${key}`;
    await s3().send(
      new PutObjectCommand({
        Bucket: process.env.ATTACHMENT_BUCKET,
        Key: object,
        Body: bytes,
        ContentType: type,
        ServerSideEncryption: "aws:kms",
        SSEKMSKeyId: process.env.ATTACHMENT_KMS_KEY,
      }),
    );
    const sha = createHash("sha256").update(bytes).digest("hex");
    await c.query(
      "INSERT INTO attachments(id,department_id,collection_id,object_key,sha256,content_type) VALUES($1,$2,$3,$4,$5,$6)",
      [key, col.department_id, id, object, sha, type],
    );
    await audit(c, a, col.department_id, "ATTACHMENT_ADDED", null, {
      id: key,
      collection: id,
      sha256: sha,
    });
    return { reference: key, status: "STORED" };
  });
}
export async function download(at: any) {
  const r = await s3().send(
    new GetObjectCommand({
      Bucket: process.env.ATTACHMENT_BUCKET,
      Key: at.object_key,
    }),
  );
  const bytes = await r.Body?.transformToByteArray();
  if (!bytes || createHash("sha256").update(bytes).digest("hex") !== at.sha256)
    throw new BadRequestException("Attachment integrity failure");
  return Buffer.from(bytes);
}
