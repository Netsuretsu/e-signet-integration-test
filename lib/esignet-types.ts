export type ClaimsSource = "userinfo" | "userinfo_transport" | "id_token";

export type EsignetProfile = {
  subject: string;
  name: string;
  individualId?: string;
  picture?: string;
  birthdate?: string;
  gender?: string;
  phoneNumber?: string;
  email?: string;
  address?: string;
  claimsSource: ClaimsSource;
  expiresAt: number;
};

export type OAuthAttempt = {
  state: string;
  nonce: string;
};

export type CallbackResult =
  | { ok: true; profile: EsignetProfile }
  | { ok: false; error: string };
