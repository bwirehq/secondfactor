# Changelog

## Unreleased

- Separate privileged event worker signing keys from user-context assertions.
- Reject replayed signed application callbacks; provide a PostgreSQL-backed guard.
- Improve public documentation, quickstart presentation and SDK security guidance.

## 0.1.0 — initial release

- Embedded Go MFA engine and PostgreSQL migrations.
- TOTP enrollment/verification, recovery codes, purpose-bound proofs, and factor management.
- Signed backend API with application isolation, authoritative session callbacks, and transactional recovery/outbox.
- Go, TypeScript, and Rust clients; runnable examples; deployment and security documentation.

Published on October 21, 2026. See [v0.1.0](https://github.com/bwirehq/secondfactor/releases/tag/v0.1.0). Unreleased changes are not part of that tag.
