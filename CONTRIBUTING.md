# Contributing

Use a branch and pull request. Preserve existing authentication and API trust boundaries. Add regression tests for security-sensitive changes and update OpenAPI, SDKs, assertion fixtures, and documentation together.

Run `go test ./...`, `go vet ./...`, `go test -race ./...`, TypeScript builds/tests, Rust tests/clippy/fmt, OpenAPI validation, and secret/vulnerability checks. Configure `SECONDFACTOR_TEST_DATABASE_URL` to an isolated disposable PostgreSQL database; tests create/drop private schemas. `SF_REQUIRE_DB=1` turns missing database configuration into failure.

Never use a production database for tests. Never commit credentials. Deterministic seeds under `testdata/` are public test fixtures, not deployable keys.

Required GitHub Actions must pass on the exact candidate commit. Never retag a release; ship a new version for fixes. See `docs/releasing.md`.
