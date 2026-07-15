// Frontière de sécurité principale du Relying Party.
// Tout ce qui touche aux secrets, à la signature et à la validation des jetons
// vit ici, côté serveur uniquement. Rien de ce fichier ne doit être importé
// dans un composant client.
//
// Dépendance : jose (npm install jose)

import {
  SignJWT,
  importPKCS8,
  jwtVerify,
  createRemoteJWKSet,
  EncryptJWT,
  jwtDecrypt,
  type JWTPayload,
} from "jose";
import { createHash, randomUUID } from "node:crypto";
import type {
  EsignetProfile,
  OAuthAttempt,
  CallbackResult,
  ClaimsSource,
} from "./esignet-types";


function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Variable d'environnement manquante : ${name}`);
  return v;
}

const CLIENT_ID = requireEnv("ESIGNET_CLIENT_ID");
const KEY_ID = requireEnv("ESIGNET_KEY_ID");
const ISSUER = requireEnv("ESIGNET_ISSUER");
const TOKEN_URL = requireEnv("ESIGNET_TOKEN_URL");
const USERINFO_URL = requireEnv("ESIGNET_USERINFO_URL");
const JWKS_URL = requireEnv("ESIGNET_JWKS_URL");
const PRIVATE_KEY_PEM = requireEnv("ESIGNET_PRIVATE_KEY").replace(/\\n/g, "\n");
const SESSION_SECRET = requireEnv("ESIGNET_SESSION_SECRET");
const ALLOW_UNVERIFIED_USERINFO =
  process.env.ESIGNET_ALLOW_UNVERIFIED_USERINFO === "true";

const SESSION_MIN = 5 * 60;
const SESSION_MAX = 60 * 60;


let privateKeyPromise: Promise<CryptoKey> | null = null;
function getPrivateKey() {
  privateKeyPromise ??= importPKCS8(PRIVATE_KEY_PEM, "RS256");
  return privateKeyPromise;
}

const remoteJwks = createRemoteJWKSet(new URL(JWKS_URL));

const sessionKey = createHash("sha256").update(SESSION_SECRET).digest();


async function buildClientAssertion(): Promise<string> {
  const key = await getPrivateKey();
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: KEY_ID })
    .setIssuer(CLIENT_ID) // iss = client_id
    .setSubject(CLIENT_ID) // sub = client_id
    .setAudience(TOKEN_URL) // aud = token endpoint exact
    .setJti(randomUUID()) // usage unique
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
}

type TokenResponse = {
  access_token: string;
  id_token: string;
  token_type: string;
  expires_in?: number;
};

async function exchangeCode(
  code: string,
  redirectUri: string,
): Promise<TokenResponse> {
  const assertion = await buildClientAssertion();

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: CLIENT_ID,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion,
  });

  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
    cache: "no-store",
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new AuthError("token_exchange", `HTTP ${res.status} ${detail.slice(0, 200)}`);
  }
  return (await res.json()) as TokenResponse;
}

async function validateIdToken(
  idToken: string,
  expectedNonce: string,
): Promise<JWTPayload> {
  let payload: JWTPayload;
  try {
    const verified = await jwtVerify(idToken, remoteJwks, {
      issuer: ISSUER,
      audience: CLIENT_ID,
      algorithms: ["RS256"],
    });
    payload = verified.payload;
  } catch (e) {
    throw new AuthError("id_token_validation", String(e));
  }

  // Comparaison stricte du nonce anti-rejeu.
  if (!payload.nonce || payload.nonce !== expectedNonce) {
    throw new AuthError("nonce_validation", "nonce absent ou différent");
  }
  if (!payload.sub) {
    throw new AuthError("id_token_validation", "sub absent");
  }
  return payload;
}

type RawClaims = Record<string, unknown>;

async function loadUserInfo(
  accessToken: string,
  idSub: string,
): Promise<{ claims: RawClaims; source: ClaimsSource } | null> {
  let res: Response;
  try {
    res = await fetch(USERINFO_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
      cache: "no-store",
    });
  } catch (e) {
    throw new AuthError("userinfo_validation", `réseau: ${String(e)}`);
  }
  if (!res.ok) {
    throw new AuthError("userinfo_validation", `HTTP ${res.status}`);
  }

  const contentType = res.headers.get("content-type") ?? "";
  const raw = await res.text();

  const looksLikeJws =
    contentType.includes("application/jwt") || /^[\w-]+\.[\w-]+\.[\w-]+$/.test(raw.trim());

  if (looksLikeJws) {
    try {
      const { payload } = await jwtVerify(raw.trim(), remoteJwks, {
        algorithms: ["RS256"],
      });
      const claims = payload as RawClaims;
      if (!checkContinuity(claims, idSub)) {
        return null; // continuité rompue : on ignore UserInfo
      }
      return { claims, source: "userinfo" };
    } catch (e) {
      // La signature ne se vérifie pas avec les clés publiées.
      // On n'accepte le repli transport QUE si l'exception est explicitement autorisée
      // et que l'endpoint est bien sur la même origine HTTPS que l'émetteur.
      if (ALLOW_UNVERIFIED_USERINFO && sameHttpsOrigin(USERINFO_URL, ISSUER)) {
        const claims = decodeJwsPayloadUnsafe(raw.trim());
        if (claims && checkContinuity(claims, idSub)) {
          return { claims, source: "userinfo_transport" };
        }
      }
      throw new AuthError("userinfo_validation", `JWS non vérifiable: ${String(e)}`);
    }
  }

  // Cas 2 : réponse JSON en clair. On exige un transport HTTPS de confiance
  // et la continuité du sujet.
  if (contentType.includes("application/json")) {
    let claims: RawClaims;
    try {
      claims = JSON.parse(raw) as RawClaims;
    } catch {
      throw new AuthError("userinfo_validation", "JSON invalide");
    }
    if (!checkContinuity(claims, idSub)) return null;
    // Une réponse JSON n'est pas cryptographiquement signée : on la classe en transport.
    const source: ClaimsSource =
      ALLOW_UNVERIFIED_USERINFO && sameHttpsOrigin(USERINFO_URL, ISSUER)
        ? "userinfo_transport"
        : "userinfo_transport";
    return { claims, source };
  }

  throw new AuthError("userinfo_validation", `Content-Type inattendu: ${contentType}`);
}

// Continuité : le sub d'UserInfo doit correspondre à celui de l'ID token.
function checkContinuity(claims: RawClaims, idSub: string): boolean {
  const sub = typeof claims.sub === "string" ? claims.sub : undefined;
  return !!sub && sub === idSub;
}

function sameHttpsOrigin(a: string, b: string): boolean {
  try {
    const ua = new URL(a);
    const ub = new URL(b);
    return ua.protocol === "https:" && ua.origin === ub.origin;
  } catch {
    return false;
  }
}

function decodeJwsPayloadUnsafe(jws: string): RawClaims | null {
  try {
    const [, payload] = jws.split(".");
    const json = Buffer.from(payload, "base64url").toString("utf8");
    return JSON.parse(json) as RawClaims;
  } catch {
    return null;
  }
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v : undefined;
}

function safePicture(v: unknown): string | undefined {
  const s = str(v);
  if (!s || s.length > 2048) return undefined;
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:" ? s : undefined;
  } catch {
    return undefined;
  }
}

function mapProfile(
  idPayload: JWTPayload,
  userInfo: { claims: RawClaims; source: ClaimsSource } | null,
  expiresAt: number,
): EsignetProfile {
  const c: RawClaims = userInfo?.claims ?? {};
  const source: ClaimsSource = userInfo?.source ?? "id_token";
  const subject = String(idPayload.sub);

  const address = (() => {
    const a = c.address as Record<string, unknown> | string | undefined;
    if (typeof a === "string") return str(a);
    if (a && typeof a === "object") {
      const formatted = str(a.formatted);
      if (formatted) return formatted;
      return (
        [a.street_address, a.locality, a.region, a.postal_code, a.country]
          .map((p) => str(p))
          .filter(Boolean)
          .join(", ") || undefined
      );
    }
    return undefined;
  })();

  return {
    subject,
    name: str(c.name) ?? "Utilisateur eSignet",
    individualId: str(c.individual_id),
    picture: safePicture(c.picture),
    birthdate: str(c.birthdate),
    gender: str(c.gender),
    phoneNumber: str(c.phone_number),
    email: str(c.email),
    address,
    claimsSource: source,
    expiresAt,
  };
}

export async function encryptSession(profile: EsignetProfile): Promise<string> {
  return new EncryptJWT({ profile })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(Math.floor(profile.expiresAt / 1000))
    .encrypt(sessionKey);
}

export async function decryptSession(
  token: string,
): Promise<EsignetProfile | null> {
  try {
    const { payload } = await jwtDecrypt(token, sessionKey);
    const profile = payload.profile as EsignetProfile | undefined;
    if (!profile || typeof profile.subject !== "string") return null;
    if (profile.expiresAt <= Date.now()) return null;
    return profile;
  } catch {
    return null;
  }
}

export async function completeAuthentication(params: {
  code: string;
  redirectUri: string;
  attempt: OAuthAttempt;
}): Promise<CallbackResult> {
  try {
    const tokens = await exchangeCode(params.code, params.redirectUri);
    const idPayload = await validateIdToken(tokens.id_token, params.attempt.nonce);
    const userInfo = await loadUserInfo(tokens.access_token, String(idPayload.sub));

    // Durée de session bornée : on part de expires_in fourni, sinon 1 h, borné [5 min, 1 h].
    const requested = tokens.expires_in ? tokens.expires_in : SESSION_MAX;
    const clamped = Math.min(Math.max(requested, SESSION_MIN), SESSION_MAX);
    const expiresAt = Date.now() + clamped * 1000;

    const profile = mapProfile(idPayload, userInfo, expiresAt);
    return { ok: true, profile };
  } catch (e) {
    // On journalise l'étape (stage) sans jamais écrire de valeur sensible.
    const stage = e instanceof AuthError ? e.stage : "unknown";
    console.warn(
      JSON.stringify({
        event: "eSignet authentication failed",
        level: "error",
        stage,
      }),
    );
    return { ok: false, error: "invalid_callback" };
  }
}

export function sessionMaxAgeSeconds(profile: EsignetProfile): number {
  return Math.max(
    1,
    Math.floor((profile.expiresAt - Date.now()) / 1000),
  );
}

class AuthError extends Error {
  constructor(public stage: string, message: string) {
    super(message);
    this.name = "AuthError";
  }
}
