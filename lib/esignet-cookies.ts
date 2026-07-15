import type { NextResponse } from "next/server";

export const OAUTH_COOKIE = "esignet_oauth";
export const SESSION_COOKIE = "esignet_session";

const BASE_ATTRS = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
  path: "/",
};

export function setOAuthCookie(res: NextResponse, value: string) {
  res.cookies.set(OAUTH_COOKIE, value, { ...BASE_ATTRS, maxAge: 10 * 60 });
}

export function setSessionCookie(
  res: NextResponse,
  value: string,
  maxAgeSeconds: number,
) {
  res.cookies.set(SESSION_COOKIE, value, {
    ...BASE_ATTRS,
    maxAge: maxAgeSeconds,
  });
}

function expire(res: NextResponse, name: string) {
  res.cookies.set(name, "", {
    ...BASE_ATTRS,
    maxAge: 0,
    expires: new Date(0),
  });
}

export function clearOAuthCookie(res: NextResponse) {
  expire(res, OAUTH_COOKIE);
}

export function clearSessionCookie(res: NextResponse) {
  expire(res, SESSION_COOKIE);
}

export function clearAllCookies(res: NextResponse) {
  expire(res, OAUTH_COOKIE);
  expire(res, SESSION_COOKIE);
}
