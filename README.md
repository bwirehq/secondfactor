# SecondFactor

*Self-hostable multi-factor authentication for modern applications.*

A Go-powered MFA library and service providing authenticator verification, recovery codes, session-bound proofs, and secure factor management through a language-independent API.

SecondFactor adds an authentication step to your existing login system. It does not register users, replace your identity provider, or decide your application's authorization policies.

## Integration options

| Application | Integration |
|---|---|
| Go | Embedded library or signed HTTP client |
| Node.js / TypeScript / NestJS | Backend TypeScript HTTP client |
| Rust | Backend Rust HTTP client |
| Python and other languages | Versioned JSON API and OpenAPI 3 |

The first release supports authenticator-app TOTP and one-time recovery codes. TOTP is **not phishing-resistant**. Passkeys, SMS, email OTP, billing, and hosted dashboards are outside v0.1.0.

## Quick start

```sh
git clone https://github.com/bwirehq/secondfactor.git
cd secondfactor
sh scripts/dev-setup.sh
docker compose up --build -d
python3 scripts/smoke.py
```

This creates ignored development keys and a short-lived self-signed certificate. It runs PostgreSQL, the MFA API, and an HTTPS mock-primary-auth application. The smoke test covers login through enrollment, confirmation, verification, a protected route, recovery-code regeneration, and logout. It waits for the next TOTP period because codes cannot be replayed.

Read [the complete quickstart](docs/quickstart.md), including manual authenticator setup and production differences.

## Go installation

After the verified v0.1.0 release is published:

```sh
go get github.com/bwirehq/secondfactor@v0.1.0
```

For untagged candidates, use the exact verified Git commit instead. See [embedded integration](docs/integrations.md). The service and Go client are separate packages within the same module.

The TypeScript and Rust SDKs are **source distributions, not published npm/crates.io packages**. Build/install them from `sdk/typescript` and `sdk/rust`; see their integration instructions. Never put application signing seeds in browser JavaScript.

## Security model

Registered backends sign short-lived, request-bound Ed25519 assertions. Tenant identity comes from the verified signer. Current primary sessions are checked through authenticated application callbacks; application credentials alone do not prove a user's session is active. The embedded API requires trusted middleware inputs.

Secrets use authenticated encryption, proofs and recovery codes are hashed, and PostgreSQL transactions serialize security transitions. Assisted recovery blocks normal MFA until session revocation is confirmed and the owner authenticates again and replaces their factor.

Deployment requires explicit issuer/key configuration, PostgreSQL, and authoritative session and recovery integrations. Use HTTPS, least-privilege database access, protected key files, and backups. Positive session decisions are not cached. There is no claim of certification or a guarantee of security. Read [security](docs/security.md), [recovery](docs/recovery.md), and [configuration](docs/configuration.md).

## Documentation

- [Architecture](docs/architecture.md) and [API reference](docs/api.md)
- [OpenAPI](docs/openapi.yaml) and [assertion protocol](docs/assertions.md)
- [Configuration](docs/configuration.md), [key rotation](docs/key-rotation.md), [troubleshooting](docs/troubleshooting.md)
- [Go, NestJS, Rust, and HTTP integrations](docs/integrations.md)
- [Coding-agent integration guide](docs/for-coding-agents.md)
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md), and [release gates](docs/releasing.md)

Licensed under [MIT](LICENSE).
