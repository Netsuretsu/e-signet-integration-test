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

type EsignetConfig = {
  clientId: string;
  keyId: string;
  issuer: string;
  tokenUrl: string;
  userInfoUrl: string;
  jwksUrl: string;
  privateKeyPem: string;
  sessionSecret: string;
  allowUnverifiedUserInfo: boolean;
};

let cachedConfig: EsignetConfig | null = null;


function getConfig(): EsignetConfig {
  if (cachedConfig) return cachedConfig;
  cachedConfig = {
    clientId: requireEnv("ESIGNET_CLIENT_ID"),
    keyId: requireEnv("ESIGNET_KEY_ID"),
    issuer: requireEnv("ESIGNET_ISSUER"),
    tokenUrl: requireEnv("ESIGNET_TOKEN_URL"),
    userInfoUrl: requireEnv("ESIGNET_USERINFO_URL"),
    jwksUrl: requireEnv("ESIGNET_JWKS_URL"),
    privateKeyPem: requireEnv("ESIGNET_PRIVATE_KEY").replace(/\\n/g, "\n"),
    sessionSecret: requireEnv("ESIGNET_SESSION_SECRET"),
    allowUnverifiedUserInfo:
      process.env.ESIGNET_ALLOW_UNVERIFIED_USERINFO === "true",
  };
  return cachedConfig;
}

const SESSION_MIN = 5 * 60;
const SESSION_MAX = 60 * 60;


let privateKeyPromise: Promise<CryptoKey> | null = null;
function getPrivateKey() {
  privateKeyPromise ??= importPKCS8(getConfig().privateKeyPem, "RS256");
  return privateKeyPromise;
}

let jwksResolver: ReturnType<typeof createRemoteJWKSet> | null = null;
function getJwks() {
  jwksResolver ??= createRemoteJWKSet(new URL(getConfig().jwksUrl));
  return jwksResolver;
}

let sessionKeyCache: Buffer | null = null;
function getSessionKey(): Buffer {
  sessionKeyCache ??= createHash("sha256")
    .update(getConfig().sessionSecret)
    .digest();
  return sessionKeyCache;
}

async function buildClientAssertion(): Promise<string> {
  const cfg = getConfig();
  const key = await getPrivateKey();
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: cfg.keyId })
    .setIssuer(cfg.clientId) // iss = client_id
    .setSubject(cfg.clientId) // sub = client_id
    .setAudience(cfg.tokenUrl) // aud = token endpoint exact
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
  const cfg = getConfig();
  const assertion = await buildClientAssertion();

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: cfg.clientId,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion,
  });

  const res = await fetch(cfg.tokenUrl, {
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
    throw new AuthError(
      "token_exchange",
      `HTTP ${res.status} ${detail.slice(0, 200)}`,
    );
  }
  return (await res.json()) as TokenResponse;
}

async function validateIdToken(
  idToken: string,
  expectedNonce: string,
): Promise<JWTPayload> {
  const cfg = getConfig();
  let payload: JWTPayload;
  try {
    const verified = await jwtVerify(idToken, getJwks(), {
      issuer: cfg.issuer,
      audience: cfg.clientId,
      algorithms: ["RS256"],
    });
    payload = verified.payload;
  } catch (e) {
    throw new AuthError("id_token_validation", String(e));
  }

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
  const cfg = getConfig();
  let res: Response;
  try {
    res = await fetch(cfg.userInfoUrl, {
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
    contentType.includes("application/jwt") ||
    /^[\w-]+\.[\w-]+\.[\w-]+$/.test(raw.trim());

  if (looksLikeJws) {
    try {
      const { payload } = await jwtVerify(raw.trim(), getJwks(), {
        algorithms: ["RS256"],
      });
      const claims = payload as RawClaims;
      if (!checkContinuity(claims, idSub)) {
        return null; // continuité rompue : on ignore UserInfo
      }
      return { claims, source: "userinfo" };
    } catch (e) {
      if (
        cfg.allowUnverifiedUserInfo &&
        sameHttpsOrigin(cfg.userInfoUrl, cfg.issuer)
      ) {
        const claims = decodeJwsPayloadUnsafe(raw.trim());
        if (claims && checkContinuity(claims, idSub)) {
          return { claims, source: "userinfo_transport" };
        }
      }
      throw new AuthError(
        "userinfo_validation",
        `JWS non vérifiable: ${String(e)}`,
      );
    }
  }

  if (contentType.includes("application/json")) {
    let claims: RawClaims;
    try {
      claims = JSON.parse(raw) as RawClaims;
    } catch {
      throw new AuthError("userinfo_validation", "JSON invalide");
    }
    if (!checkContinuity(claims, idSub)) return null;
    return { claims, source: "userinfo_transport" };
  }

  throw new AuthError(
    "userinfo_validation",
    `Content-Type inattendu: ${contentType}`,
  );
}

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

// Mapping vers le profil applicatif
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

// 6. Session JWE (dir + A256GCM)
export async function encryptSession(profile: EsignetProfile): Promise<string> {
  return new EncryptJWT({ profile })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(Math.floor(profile.expiresAt / 1000))
    .encrypt(getSessionKey());
}

export async function decryptSession(
  token: string,
): Promise<EsignetProfile | null> {
  try {
    const { payload } = await jwtDecrypt(token, getSessionKey());
    const profile = payload.profile as EsignetProfile | undefined;
    if (!profile || typeof profile.subject !== "string") return null;
    if (profile.expiresAt <= Date.now()) return null;
    return profile;
  } catch {
    return null;
  }
}

// Orchestration complète : appelée par la route de callback.
export async function completeAuthentication(params: {
  code: string;
  redirectUri: string;
  attempt: OAuthAttempt;
}): Promise<CallbackResult> {
  try {
    const tokens = await exchangeCode(params.code, params.redirectUri);
    const idPayload = await validateIdToken(
      tokens.id_token,
      params.attempt.nonce,
    );
    const userInfo = await loadUserInfo(
      tokens.access_token,
      String(idPayload.sub),
    );

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

// Durée max de session exposée pour poser le cookie.
export function sessionMaxAgeSeconds(profile: EsignetProfile): number {
  return Math.max(1, Math.floor((profile.expiresAt - Date.now()) / 1000));
}

// Erreur interne qui transporte l'étape du pipeline pour la taxonomie des logs.
class AuthError extends Error {
  constructor(
    public stage: string,
    message: string,
  ) {
    super(message);
    this.name = "AuthError";
  }
}