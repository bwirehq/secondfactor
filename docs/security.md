# Security model and operational responsibilities

Protected assets include authenticator seeds, recovery codes, MFA proof integrity, tenant isolation, primary session ownership, recovery authorization, audit evidence, and release integrity.

The threat model assumes attackers can send arbitrary HTTP requests, replay captured assertions or codes, race operations, control another registered application's inputs, and influence DNS. It does not assume a trusted application backend or operator private key remains trustworthy after compromise.

Controls include explicit tenant-scoped keys/queries; exact request-bound signatures; assertion replay storage; authoritative primary-session callbacks; monotonic TOTP watermarks; row locks and single-transaction failed-attempt commits; purpose-bound proofs; AES-256-GCM with unambiguous AAD; and an explicitly blocked recovery state machine.

A registered application backend can assert identities for its own tenant. Protect its signing seed and primary-auth middleware. Its credential alone never substitutes for the authoritative session check. Applications cannot assert another tenant unless they control that tenant's signing key.

TOTP is susceptible to phishing and real-time relay. It is not equivalent to WebAuthn/passkeys or hardware security keys. This project does not promise certification or guaranteed security.

Never log secrets, provisioning URIs, codes, proofs, signed authorization headers, callback bodies, or event-delivery secrets. Configure reverse proxies accordingly. Keep sensitive response bodies out of telemetry, crash reports, and distributed tracing.

Callbacks use DNS-address validation at connection time, direct dialing, authenticated correlated responses, TLS, disabled redirects, and two-second deadlines. Any explicit private-CIDR exception is an operator trust decision. Restrict permitted destinations with network egress policy as well.

Use separate database roles, protected configuration/key files, current runtime/security updates, encrypted backups, time synchronization, and monitored outbox delivery. Account-based rate limits can intentionally deny further attempts after abuse; applications need a support/recovery policy.

Session checks are point-in-time: the application remains responsible for its own authorization and for immediately enforcing primary-session revocation on its protected routes. Do not cache successful MFA/session decisions or treat MFA as a substitute for primary authentication.

See `SECURITY.md` for reporting and `docs/releasing.md` for review gates. Initial source-review findings and runtime tests do not establish an independent certification.
