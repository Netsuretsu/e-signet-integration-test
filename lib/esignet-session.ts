import { cookies } from "next/headers";
import { decryptSession } from "./esignet-auth";
import { SESSION_COOKIE } from "./esignet-cookies";
import type { EsignetProfile } from "./esignet-types";

export async function getEsignetSession(): Promise<EsignetProfile | null> {
  const store = await cookies();
  const raw = store.get(SESSION_COOKIE)?.value;
  if (!raw) return null;
  return decryptSession(raw);
}
