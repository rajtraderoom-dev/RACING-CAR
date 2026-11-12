import { ForbiddenException, UnauthorizedException } from "@nestjs/common";
import { createHash } from "node:crypto";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { PoolClient } from "pg";
export function localPanelEnabled() {
  return (
    process.env.LOCAL_CONTROL_PANEL === "true" &&
    process.env.NODE_ENV !== "production"
  );
}
export function requireLocalPanel() {
  if (!localPanelEnabled())
    throw new ForbiddenException("Local control panel is disabled");
}
export function webOrigin() {
  const origin = process.env.WEB_ORIGIN ?? "https://localhost:8443";
  const u = new URL(origin);
  if (u.hostname !== "localhost" || u.protocol !== "https:")
    throw Error("Control panel must use HTTPS localhost");
  return u.origin;
}
export const webChallenge = (message: string) =>
  createHash("sha256").update(message).digest("base64url");
export async function verifyWeb(
  c: PoolClient,
  deviceId: string,
  credential: any,
  assertion: any,
  message: string,
) {
  requireLocalPanel();
  const response = await verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: webChallenge(message),
    expectedOrigin: webOrigin(),
    expectedRPID: "localhost",
    credential: {
      id: credential.id,
      publicKey: new Uint8Array(Buffer.from(credential.publicKey, "base64url")),
      counter: credential.counter,
      transports: credential.transports,
    },
    requireUserVerification: true,
  });
  if (!response.verified || !response.authenticationInfo.userVerified)
    throw new UnauthorizedException();
  await c.query(
    "UPDATE devices SET webauthn=jsonb_set(webauthn,'{counter}',$1::jsonb) WHERE id=$2",
    [JSON.stringify(response.authenticationInfo.newCounter), deviceId],
  );
  return true;
}
