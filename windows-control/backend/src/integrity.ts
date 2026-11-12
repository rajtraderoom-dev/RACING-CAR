import { UnauthorizedException } from "@nestjs/common";
import { GoogleAuth } from "google-auth-library";
import { createHash } from "node:crypto";
export async function integrity(
  token: string | undefined,
  message: string,
  hardwareVerified: boolean,
) {
  if (
    process.env.ALLOW_UNATTESTED_DEV === "true" &&
    process.env.NODE_ENV !== "production"
  )
    return;
  if (
    !hardwareVerified ||
    !token ||
    !process.env.ANDROID_CERT_SHA256 ||
    !process.env.ANDROID_PACKAGE
  )
    throw new UnauthorizedException("Verified device and integrity required");
  const auth = new GoogleAuth({
    scopes: ["https://www.googleapis.com/auth/playintegrity"],
  });
  const client = await auth.getClient();
  try {
    const r = await client.request<any>({
      url: `https://playintegrity.googleapis.com/v1/${process.env.ANDROID_PACKAGE}:decodeIntegrityToken`,
      method: "POST",
      data: { integrity_token: token },
    });
    const p = r.data.tokenPayloadExternal;
    const nonce = createHash("sha256").update(message).digest("base64url");
    const age = Date.now() - Number(p.requestDetails.timestampMillis);
    if (
      p.requestDetails.requestPackageName !== process.env.ANDROID_PACKAGE ||
      p.requestDetails.nonce !== nonce ||
      age < 0 ||
      age > 60000 ||
      p.appIntegrity.appRecognitionVerdict !== "PLAY_RECOGNIZED" ||
      p.appIntegrity.packageName !== process.env.ANDROID_PACKAGE ||
      !p.appIntegrity.certificateSha256Digest?.includes(
        process.env.ANDROID_CERT_SHA256,
      ) ||
      !p.deviceIntegrity.deviceRecognitionVerdict?.includes(
        "MEETS_STRONG_INTEGRITY",
      )
    )
      throw Error();
  } catch {
    throw new UnauthorizedException("Integrity verification failed");
  }
}
