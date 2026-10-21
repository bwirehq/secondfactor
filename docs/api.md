# HTTP API

All endpoints use JSON over HTTPS, signed backend assertions, and `Cache-Control: no-store`. Browsers must call their own application backend; requests with an Origin header are rejected. Maximum body: 16 KiB. Responses contain structured `error: {code, message, retry_after?}` envelopes on failure.

| Method/path | Input | Success |
|---|---|---|
| POST `/v1/enrollments` | account_name, optional replacement proof | secret, provisioning URI, expiry |
| POST `/v1/enrollments/confirm` | code, optional replacement proof | ten recovery codes, access and sensitive proofs |
| POST `/v1/verifications/totp` | code | distinct access/sensitive proofs |
| POST `/v1/verifications/sensitive` | code | distinct access/sensitive proofs |
| POST `/v1/verifications/recovery-code` | code | replacement-only proof |
| POST `/v1/proofs/validate` | proof, purpose: access or sensitive | ok |
| GET `/v1/factors/status` | empty body | enrolled, recovery_pending, remaining codes, version |
| POST `/v1/recovery-codes/regenerate` | sensitive proof | ten new codes |
| POST `/v1/factors/replace` | account_name, sensitive/replacement proof | pending secret, URI, expiry |
| DELETE `/v1/factors` | sensitive proof | ok |
| POST `/v1/sessions/revoke` | empty object | ok; deletes this session's MFA proofs/grants |
| POST `/v1/assisted-recovery` | target, reason, evidence, job_id | job ID/state |
| POST `/v1/assisted-recovery/resume` | target, reason, evidence, job_id | job ID/state |
| POST `/v1/assisted-recovery/complete` | job_id, invitation | replacement-only proof |
| POST `/v1/assisted-recovery/cancel` | target, reason, evidence, job_id | ok; remains blocked |
| POST `/v1/events/claim` | empty object | at most 20 tenant events with lease tokens |
| POST `/v1/events/ack` | event_id, lease | ok |
| GET `/v1/health/ready` | empty body | ok if database reachable |

Enrollment start, confirmation, regeneration, replacement, factor/session revocation, recovery start/complete/cancel require `Idempotency-Key` of 16–128 characters. One-time results are never redisclosed; completed retries return `409 idempotent_secret_consumed`. Lost initial codes require a fresh supported authentication/recovery path, not replaying the original response. A lost initial enrollment URI expires after ten minutes and can then be restarted.

HTTP errors: 400 invalid_input; 401 invalid_code; 403 denied; 409 conflict/recovery_pending/idempotent_secret_consumed; 429 rate_limited with Retry-After; 503 unavailable. Unknown endpoints return 404. No error includes secrets or internal database details.

Event claim/ack is privileged backend delivery access scoped to the signing application. It does not represent user authorization. Do not proxy it to browsers. Recovery invitation delivery can contain one-time sensitive material; encrypt delivery, avoid logs, and use a verified notification channel. Acknowledge only after successful delivery. Leases last 30 seconds; consumers deduplicate by event ID.

## Direct HTTP

Create the signed assertion locally in a trusted backend using the protocol, then send it through a protected header file rather than putting credentials in a command argument:

```sh
# headers.txt (mode 0600) contains Authorization, Content-Type and Idempotency-Key.
# request.json contains the exact signed JSON bytes; assertion must be fresh.
curl --fail-with-body --cacert service-ca.pem \
  --header @headers.txt --data-binary @request.json \
  https://mfa.example.invalid/v1/enrollments
```

This illustrative domain is a placeholder. Never send secrets in URLs. See [OpenAPI](openapi.yaml), [assertion protocol](assertions.md), and [recovery](recovery.md).
