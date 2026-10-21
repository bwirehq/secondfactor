# Integration guide for coding agents

1. Inspect the application's existing primary authentication, sessions, authorization, database, and deployment. Do not replace its identity provider or user model.
2. Choose embedded Go or backend HTTP integration. Never put backend signing seeds in browser/mobile code.
3. Implement authoritative session lookup. Return session subject, ID, active state, expiry, authentication time, and the immutable generation recorded at session establishment.
4. Implement independent recovery policy. Bind decisions to action, actor, target, reason, evidence reference, and job ID. Do not use an administrator flag as sole evidence.
5. Implement durable, idempotent generation-based session revocation. Increment generation and enforce it against all old sessions before confirming completion.
6. Register application keys and issuer out of band. Keep encryption and signing keys separate and outside the database.
7. Apply migrations explicitly. Start only after application registration and key-coverage checks succeed.
8. Resolve trusted identity and source from authenticated backend middleware. Never accept browser-submitted subject/session/source claims as trusted context.
9. Add enrollment and code-entry UX. Display recovery codes only once; use local QR generation if desired. Require access proofs for normal protected routes and separate sensitive proofs for factor changes.
10. Preserve CSRF, cookie, origin, primary-auth, and application authorization controls. Integrate logout, session invalidation, outbox notification delivery, failure monitoring, and backup/restore procedures.
11. Test cross-session/tenant rejection, code replay, callback failures, recovery blocking, key rotation, and concurrent mutations.

Check actual exports and OpenAPI before writing integration code. Do not invent SDK publications, bypass failed callbacks, cache successful session verification, or treat recovery grants as access proofs. Handle `idempotent_secret_consumed` explicitly: the original mutation completed, but its one-time secret will not be returned again.
