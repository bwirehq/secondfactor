# Troubleshooting

- `invalid_input`: check required fields, source context, JSON schema, key sizes, and 16–128-character idempotency keys.
- `denied`: verify audience, application/key registration, exact signed method/path/body/idempotency hash, current primary session, and required proof purpose.
- `invalid_code`: code is malformed, expired, incorrect, or already used. Enrollment confirmation consumes its code; wait for a new TOTP period.
- `conflict`: another enrollment or state transition won. Do not retry with altered payload under the same idempotency key.
- `idempotent_secret_consumed`: the operation already committed. Do not regenerate secrets implicitly; use a documented fresh-authentication or recovery path.
- `recovery_pending`: assisted recovery or a consumed recovery code requires factor replacement. Fix/confirm revocation and complete owner recovery; do not clear the database flag manually.
- `rate_limited`: honor retry metadata. Check account, session, source, application, and operation budgets.
- `unavailable`: inspect sanitized service health, database connectivity, key coverage, callback TLS/signature/timeout, and network allowlists. Never print callback or request secrets to debug it.
- Startup schema failure: explicitly run `migrate` with appropriate credentials before `serve`.
- Private callback blocked: add only the intended destination CIDR and configure trusted CA roots. Do not disable validation globally.
- Compose secret permission failure: regenerate `.env` with host UID/GID via the setup script. Secrets remain mode 0600.
- Compose subnet conflict: choose a dedicated nonconflicting subnet and update the callback CIDR allowlist together.
- Tests skipped: configure an isolated database; set `SF_REQUIRE_DB=1` to require integration coverage. Mandatory release CI must not skip it.

A primary-session callback outage denies MFA operations. Restore the integration rather than weakening authentication. Preserve blocked recovery jobs and retry the same idempotent revocation job after repair.
