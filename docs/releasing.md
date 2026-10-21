# Release gates

Do not create `v0.1.0` until every mandatory gate passes on the exact candidate commit.

1. Verify publishing ownership and inspect repository conflicts.
2. Push an untagged candidate with fresh history and reviewed files.
3. Require green `required-ci / verify`: Go unit/PostgreSQL/race/vet/vulnerability checks, TypeScript SDK/NestJS, Rust SDK/example/audit, live cross-language checks, OpenAPI, secret/hygiene checks, container startup, and deployed full lifecycle.
4. Independently review that candidate's security-sensitive source, record findings/limitations, resolve critical/high findings, and rerun checks after fixes.
5. In a clean external module, install `github.com/bwirehq/secondfactor@<candidate SHA>` without replacements and run a consumer smoke test.
6. Verify all required checks correspond to that same SHA and are not skipped. Create immutable annotated tag `v0.1.0` on that SHA and publish the GitHub release.
7. Verify proxy resolution, fresh external exact-version installation, and a fresh deployment from published sources.
8. Record release URLs, CI evidence, independent review scope/status, and source-only SDK distribution status.

GitHub Actions is the pre-tag verification runner even if local Rust or Docker tooling is unavailable. Never publish first and use CI to discover whether the release builds. Never move or overwrite a public release tag. If verification fails after publication, disclose the limitation and correct it through a new version.

The TypeScript/Rust manifests intentionally disable registry publication until ownership, naming, credentials, and package verification are separately established. Do not advertise npm/crates.io availability.


## Repository protection

Require successful branch CI and review through GitHub branch rules. Restrict force pushes and protect public version tags from deletion or retargeting. Prefer signed tags and verifiable release provenance. Repository administrators must configure these settings; successful CI by itself cannot enforce them.
