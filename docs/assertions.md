# Assertion wire protocol v1

Only trusted application backends call the service. Use `Authorization: Bearer <compact-JWS>` over HTTPS. Register Ed25519 public keys out of band; no runtime JWK URL fetching is allowed.

Header: `alg=EdDSA`, `typ=sf-assertion+jwt`, and a registered `kid`. Only Ed25519 keys are accepted.

| Claim | Required meaning |
|---|---|
| `idh` | Base64url SHA-256 of the exact `Idempotency-Key` header value; hash empty bytes if absent |
| `ver` | Integer 1 |
| `iss` | Registered application ID |
| `aud` | Exact deployment audience |
| `sub` | Trusted authenticated subject |
| `sid` | Trusted primary session ID |
| `iat`, `exp` | Integer Unix seconds; validity at most 60 seconds |
| `jti` | Unique random identifier, maximum 128 identifier characters |
| `htm` | Exact uppercase HTTP method |
| `htu` | Exact `/v1/...` path without query, encoding aliases, or trailing slash |
| `bsh` | Unpadded base64url SHA-256 of the exact transmitted request bytes |
| `src` | Trusted, nonempty source identifier |

Five seconds of clock tolerance is allowed. Assertions are single use across service replicas. Use a new `jti` on every retry, with the same idempotency key/body for an idempotent mutation.

Serialize the JSON body once, hash those bytes, and transmit those same bytes. GET has an empty body. The verifier checks the original JWS signing input, without reserializing JSON. Duplicate keys, unknown claims, duplicate authorization/idempotency headers, and malformed paths are rejected.

`testdata/assertion_vectors.json` contains PUBLIC NONPRODUCTION seed fixtures and exact expected signatures shared by Go, TypeScript, and Rust. Never deploy these seeds.

A valid assertion authenticates the registered application's claims. It does not prove a primary session is still active: session callbacks perform that independent check. An administrator claim/flag is never sufficient for recovery authorization.

For key rotation, register new public keys first, switch signing to the new key ID, wait beyond assertion expiry and outstanding callback deadlines, then revoke old keys. Use separate application and service callback signing keys. Do not reuse encryption keys for signing.
