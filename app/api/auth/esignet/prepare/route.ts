import { randomBytes } from "node:crypto";
import { NextResponse } from "next/server";
import { setOAuthCookie } from "@/lib/esignet-cookies";

export const dynamic = "force-dynamic";

export async function GET() {
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const attempt = Buffer.from(JSON.stringify({ state, nonce })).toString(
    "base64url",
  );

  const res = NextResponse.json(
    { state, nonce },
    { headers: { "Cache-Control": "no-store" } },
  );
  setOAuthCookie(res, attempt);
  return res;
}
