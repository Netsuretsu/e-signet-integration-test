// Déconnexion locale. Aucun endpoint global de fin de session eSignet n'est
// supposé : on se contente d'expirer les cookies OAuth et session.

import { NextResponse, type NextRequest } from "next/server";
import { clearAllCookies } from "@/lib/esignet-cookies";

export const dynamic = "force-dynamic";

function handle(req: NextRequest) {
  const res = NextResponse.redirect(
    new URL("/login?logged_out=1", req.url),
    { status: 303 }, // force un GET sur la redirection, même après un POST
  );
  clearAllCookies(res);
  // Empêche la réutilisation d'une réponse intermédiaire.
  res.headers.set("Cache-Control", "no-store");
  return res;
}

export const GET = handle;
export const POST = handle;
