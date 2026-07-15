import { NextResponse, type NextRequest } from "next/server";
import {
  completeAuthentication,
  encryptSession,
  sessionMaxAgeSeconds,
} from "@/lib/esignet-auth";
import {
  OAUTH_COOKIE,
  clearAllCookies,
  clearOAuthCookie,
  setSessionCookie,
} from "@/lib/esignet-cookies";
import type { OAuthAttempt } from "@/lib/esignet-types";

export const dynamic = "force-dynamic";

function fail(req: NextRequest, reason: string) {
  const res = NextResponse.redirect(
    new URL(`/login?error=${reason}`, req.url),
  );
  clearAllCookies(res);
  return res;
}

export async function GET(req: NextRequest) {
  const url = new URL(req.url);

  if (url.searchParams.get("error")) {
    return fail(req, "esignet_denied");
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) {
    return fail(req, "invalid_callback");
  }

  const rawAttempt = req.cookies.get(OAUTH_COOKIE)?.value;
  if (!rawAttempt) {
    return fail(req, "invalid_callback");
  }

  let attempt: OAuthAttempt;
  try {
    attempt = JSON.parse(
      Buffer.from(rawAttempt, "base64url").toString("utf8"),
    ) as OAuthAttempt;
  } catch {
    return fail(req, "invalid_callback");
  }

  if (!attempt.state || attempt.state !== state) {
    return fail(req, "invalid_callback");
  }

  const redirectUri = `${url.origin}/auth/callback`;

  const result = await completeAuthentication({ code, redirectUri, attempt });
  if (!result.ok) {
    return fail(req, result.error);
  }

  const jwe = await encryptSession(result.profile);
  const res = NextResponse.redirect(new URL("/dashboard", req.url));
  clearOAuthCookie(res);
  setSessionCookie(res, jwe, sessionMaxAgeSeconds(result.profile));
  return res;
}
