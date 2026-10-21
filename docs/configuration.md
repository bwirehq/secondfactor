# Configuration

`secondfactor.New(Config)` validates explicit configuration: pool, registered application issuers, active encryption key and previous keys, authoritative session verifier, recovery authorizer, session revoker, and rate limits. The zero `Limits` value selects documented defaults; partial/invalid limits fail validation.

The CLI accepts `serve`, `migrate`, `rotate`, `key-usage`, `cleanup`, and `keygen`. Use `--config path.json`; `keygen --dir new-directory` creates new keys only. Encryption keys and Ed25519 seeds are base64-encoded 32-byte values. Public key files contain base64-encoded 32-byte public keys.

`database_url_file`, `encryption_keys`, and `service_key_file` reference private regular files with mode 0600 or stricter. `applications` maps application IDs to issuer, signing-key files, callback URL, optional explicit allowed CIDRs, and optional CA file. `audience` identifies this deployment. `tls_cert` and `tls_key` enable TLS; `allow_http` is an explicit operator option only for protected TLS-terminated networking.

Use `scripts/dev-setup.sh` for a complete generated example. `config.local.json`, `config.compose.json`, `.env`, and `secrets/` are ignored by Git.

Issuer has no core default. Register applications explicitly after schema migration. In embedded mode, call `RegisterApplications` and `CheckKeyCoverage` during controlled startup before accepting traffic.

Rate-limit defaults per ten-minute window: account 30, session 30, trusted source 100, application 10,000, and sensitive enrollment/recovery initiation 10. Five invalid attempts block an account for ten minutes. Aggregate buckets prevent switching endpoints from bypassing limits. Callback timeout is two seconds; API request deadline is ten seconds.

Source must come from trusted middleware. Trust forwarded IP headers only from an explicitly configured reverse proxy. Do not accept a browser-submitted IP address. Avoid exposing raw source identifiers in logs; pseudonymize them at the application boundary.

Database runtime privileges: connect, schema usage, and SELECT/INSERT/UPDATE/DELETE on SecondFactor tables only. Migration credentials additionally need schema/table/index creation. Do not grant the runtime role superuser or access to unrelated schemas. Treat event claims as privileged application-backend access; never expose them as an end-user endpoint.

Run cleanup explicitly on a controlled schedule. Expired proofs, assertion replay rows, enrollment, idempotency, and rate-limit records are removed; unfinished recovery workflows remain blocked and retained. Events are retained for at least 90 days and at least 30 days after acknowledgment. Back up recovery audit data according to your policy.
