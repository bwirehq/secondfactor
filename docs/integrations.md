# Integrations

## Embedded Go

Import `github.com/bwirehq/secondfactor`. Construct a PostgreSQL pool and call `Migrate` explicitly using migration credentials. Initialize the runtime service with application configuration, a keyring, and implementations of `SessionVerifier`, `RecoveryAuthorizer`, and `SessionRevoker`. Call `RegisterApplications` and `CheckKeyCoverage` before accepting traffic.

Resolve `Identity` from trusted application middleware. Call `BeginEnrollment`, `ConfirmEnrollment`, and `VerifyTOTP` with typed `Mutation` values. Use random idempotency keys. Store access/sensitive proofs in your backend session or secure server-managed storage; never log them. Call `ValidateProof` with the required purpose on protected requests and retain your existing primary-authentication and authorization checks.

See the root public types for exact interface signatures. Context cancellation is honored by database and callback operations. No constructor performs migrations or reads environment variables.

## Go HTTP client

Use `github.com/bwirehq/secondfactor/client.New` with service URL, audience, application ID, signing key ID, and Ed25519 private key. Each operation receives an identity resolved by your own middleware. Configure certificate trust through the supplied HTTP client. The runnable `examples/go-http` demonstrates the complete browser/backend flow.

## TypeScript and NestJS

```sh
cd sdk/typescript
npm ci --ignore-scripts
npm run build
npm test
cd ../../examples/nestjs
npm ci --ignore-scripts
npm run build
```

The SDK is not published to npm. Install its built source using a file dependency or your own reviewed internal distribution.

Construct `SecondFactorClient` with backend-only signing seed, service URL, application, key ID, and audience. Use `validateProof(identity, proof, 'access')` from a guard after existing middleware establishes a trusted primary session. The example's `TrustedRequest.primary` is an integration contract, not a header that clients can populate. Without your middleware, protected routes intentionally return 401. Use platform certificate trust (`NODE_EXTRA_CA_CERTS` for local development), not disabled certificate verification.

## Rust

The SDK is not published to crates.io. Use a reviewed path or Git revision dependency on `sdk/rust`:

```toml
secondfactor-client = { path = "../secondfactor/sdk/rust" }
```

Run `cargo test --manifest-path sdk/rust/Cargo.toml --locked` and `cargo run --manifest-path examples/rust/Cargo.toml`. Configure `SECONDFACTOR_SEED_FILE` and service URL in the example. Supply real primary-authentication middleware that inserts `TrustedSession`. The example refuses protected access without it. Set `SECONDFACTOR_CA_FILE` to the development certificate for a local service. The Rust client also supports explicit private CA trust through `new_with_ca`; normal TLS verification remains enabled.

## Other languages

Implement the assertion protocol in `docs/assertions.md` and call the versioned endpoints in OpenAPI. Do not reimplement TOTP, recovery, or proof verification. Have the service validate opaque proofs online. Public test vectors are provided for protocol interoperability.
