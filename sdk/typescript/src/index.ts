import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
export interface Identity {
  subject: string;
  session: string;
  source: string;
}
export interface Proof {
  token: string;
  purpose: "access" | "sensitive" | "replacement";
  expires_at: string;
}
export interface Verification {
  access: Proof;
  sensitive: Proof;
}
export interface Enrollment {
  secret: string;
  uri: string;
  expires_at: string;
}
export interface Confirmation {
  recovery_codes: string[];
  verification: Verification;
}
export interface Status {
  enrolled: boolean;
  recovery_pending: boolean;
  remaining_recovery_codes: number;
  version: number;
}
export interface RecoveryJob {
  job_id: string;
  state: string;
}
export interface Event {
  id: string;
  subject: string;
  kind: string;
  payload: Record<string, unknown>;
  delivery?: Record<string, unknown>;
  lease: string;
  created_at: string;
}
export interface Mutation {
  code?: string;
  proof?: string;
  account_name?: string;
  target?: string;
  reason?: string;
  evidence?: string;
  job_id?: string;
  invitation?: string;
}
export interface Claims {
  idh: string;
  ver: number;
  iss: string;
  aud: string;
  sub: string;
  sid: string;
  iat: number;
  exp: number;
  jti: string;
  htm: string;
  htu: string;
  bsh: string;
  src: string;
}
export interface Config {
  baseURL: string;
  audience: string;
  application: string;
  keyID: string;
  seed: Uint8Array;
  timeoutMs?: number;
  fetch?: typeof fetch;
}
export class SecondFactorError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly retryAfter = 0,
  ) {
    super(message);
    this.name = "SecondFactorError";
  }
}
export function bodyHash(body: Uint8Array): string {
  return createHash("sha256").update(body).digest("base64url");
}
export function signAssertion(
  seed: Uint8Array,
  keyID: string,
  claims: Claims,
): string {
  if (seed.length !== 32) throw new Error("Ed25519 seed must contain 32 bytes");
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const header = { alg: "EdDSA", typ: "sf-assertion+jwt", kid: keyID };
  const input =
    Buffer.from(JSON.stringify(header)).toString("base64url") +
    "." +
    Buffer.from(JSON.stringify(claims)).toString("base64url");
  return (
    input + "." + sign(null, Buffer.from(input), key).toString("base64url")
  );
}
export class SecondFactorClient {
  private readonly config: Config;
  constructor(config: Config) {
    const u = new URL(config.baseURL);
    if (
      u.username ||
      u.password ||
      u.search ||
      u.hash ||
      u.pathname !== "/" ||
      !(
        u.protocol === "https:" ||
        (u.protocol === "http:" &&
          ["localhost", "127.0.0.1"].includes(u.hostname))
      ) ||
      config.seed.length !== 32 ||
      !config.application ||
      !config.audience ||
      !config.keyID
    )
      throw new Error("Invalid client configuration");
    this.config = { ...config, seed: Uint8Array.from(config.seed) };
  }
  async request<T>(
    identity: Identity,
    method: string,
    path: string,
    body: unknown = undefined,
    idempotencyKey?: string,
  ): Promise<T> {
    if (
      !/^\/v1\/[a-z0-9/-]+$/.test(path) ||
      path.includes("//") ||
      path.endsWith("/")
    )
      throw new Error("Invalid API path");
    const raw = body === undefined ? "" : JSON.stringify(body);
    const now = Math.floor(Date.now() / 1000);
    const claims: Claims = {
      idh: bodyHash(Buffer.from(idempotencyKey ?? "")),
      ver: 1,
      iss: this.config.application,
      aud: this.config.audience,
      sub: identity.subject,
      sid: identity.session,
      iat: now,
      exp: now + 60,
      jti: randomBytes(24).toString("base64url"),
      htm: method,
      htu: path,
      bsh: bodyHash(Buffer.from(raw)),
      src: identity.source,
    };
    const assertion = signAssertion(
      this.config.seed,
      this.config.keyID,
      claims,
    );
    const response = await (this.config.fetch ?? fetch)(
      this.config.baseURL.replace(/\/$/, "") + path,
      {
        method,
        headers: {
          Authorization: "Bearer " + assertion,
          "Content-Type": "application/json",
          ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
        },
        body: method === "GET" ? undefined : raw,
        redirect: "error",
        signal: AbortSignal.timeout(this.config.timeoutMs ?? 10000),
      },
    );
    const chunks: Uint8Array[] = [];
    let length = 0;
    if (!response.body)
      throw new SecondFactorError("unavailable", "Empty response");
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > 1048576) {
          await reader.cancel();
          throw new SecondFactorError("unavailable", "Response too large");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const text = Buffer.concat(chunks).toString("utf8");
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      throw new SecondFactorError("unavailable", "Invalid response");
    }
    if (!response.ok) {
      const e = (
        data as {
          error?: { code?: string; message?: string; retry_after?: number };
        }
      ).error;
      throw new SecondFactorError(
        e?.code ?? "unavailable",
        e?.message ?? "Request failed",
        e?.retry_after ?? 0,
      );
    }
    return data as T;
  }
  status(i: Identity) {
    return this.request<Status>(i, "GET", "/v1/factors/status");
  }
  beginEnrollment(i: Identity, b: Mutation, key: string) {
    return this.request<Enrollment>(i, "POST", "/v1/enrollments", b, key);
  }
  confirmEnrollment(i: Identity, b: Mutation, key: string) {
    return this.request<Confirmation>(
      i,
      "POST",
      "/v1/enrollments/confirm",
      b,
      key,
    );
  }
  verifyTOTP(i: Identity, code: string) {
    return this.request<Verification>(i, "POST", "/v1/verifications/totp", {
      code,
    });
  }
  verifySensitive(i: Identity, code: string) {
    return this.request<Verification>(
      i,
      "POST",
      "/v1/verifications/sensitive",
      { code },
    );
  }
  verifyRecoveryCode(i: Identity, code: string) {
    return this.request<Proof>(i, "POST", "/v1/verifications/recovery-code", {
      code,
    });
  }
  validateProof(i: Identity, proof: string, purpose: "access" | "sensitive") {
    return this.request<{ ok: boolean }>(i, "POST", "/v1/proofs/validate", {
      proof,
      purpose,
    });
  }
  regenerateRecoveryCodes(i: Identity, proof: string, key: string) {
    return this.request<{ recovery_codes: string[] }>(
      i,
      "POST",
      "/v1/recovery-codes/regenerate",
      { proof },
      key,
    );
  }
  replaceFactor(i: Identity, b: Mutation, key: string) {
    return this.request<Enrollment>(i, "POST", "/v1/factors/replace", b, key);
  }
  revokeFactor(i: Identity, proof: string, key: string) {
    return this.request<{ ok: boolean }>(
      i,
      "DELETE",
      "/v1/factors",
      { proof },
      key,
    );
  }
  revokeSession(i: Identity, key: string) {
    return this.request<{ ok: boolean }>(
      i,
      "POST",
      "/v1/sessions/revoke",
      {},
      key,
    );
  }
  startAssistedRecovery(i: Identity, b: Mutation, key: string) {
    return this.request<RecoveryJob>(
      i,
      "POST",
      "/v1/assisted-recovery",
      b,
      key,
    );
  }
  resumeAssistedRecovery(i: Identity, b: Mutation) {
    return this.request<RecoveryJob>(
      i,
      "POST",
      "/v1/assisted-recovery/resume",
      b,
    );
  }
  completeAssistedRecovery(i: Identity, b: Mutation, key: string) {
    return this.request<Proof>(
      i,
      "POST",
      "/v1/assisted-recovery/complete",
      b,
      key,
    );
  }
  cancelAssistedRecovery(i: Identity, b: Mutation, key: string) {
    return this.request<{ ok: boolean }>(
      i,
      "POST",
      "/v1/assisted-recovery/cancel",
      b,
      key,
    );
  }
  claimEvents(i: Identity) {
    return this.request<Event[]>(i, "POST", "/v1/events/claim", {});
  }
  ackEvent(i: Identity, event_id: string, lease: string) {
    return this.request<{ ok: boolean }>(i, "POST", "/v1/events/ack", {
      event_id,
      lease,
    });
  }
}
