# Recovery and session revocation

Recovery codes permit factor replacement, not ordinary MFA access. Consuming a code increments the factor version, invalidates proofs, and blocks normal MFA operations until a new factor is confirmed. Lost or expired replacement grants require a new independently authorized recovery workflow.

Assisted recovery requires an application policy decision bound to the actor, action (`start`, `resume`, `cancel`), target, reason, evidence reference, and job ID. The application must verify independent identity evidence and administrator privileges. A boolean administrator claim is insufficient.

Persisted states: `blocked -> invited -> replacing -> completed`. `cancelled` invalidates workflow credentials but leaves the factor blocked. An authorized new job can restart recovery. Cancellation never disables the old factor or restores MFA access.

Initiation records the policy decision and pre-recovery generation, blocks sensitive MFA, and writes the revocation event atomically. No external callback occurs while holding the factor transaction.

The revocation callback must be durable and idempotent by job ID. It increments a subject-wide revocation generation and ensures all older-generation sessions are unusable before returning confirmed. On errors, timeouts, or unconfirmed results, recovery stays blocked. Resume repeats authorization and the same revocation job safely.

After confirmation, an encrypted outbox event delivers a ten-minute invitation through the application's independently verified notification channel. Completion requires an active primary session whose generation was captured when established and is at least the confirmed new generation. Its authentication timestamp must also be consistent with initiation (five-second tolerance). Do not update old sessions to newer generations. Do not weaken the generation check to accommodate clock skew.

Completing an invitation issues only a ten-minute, session-bound factor-replacement grant. Owner confirmation of a new authenticator completes the workflow, invalidates old grants/codes/proofs, and enables new proofs. A recovery invitation alone never makes a user MFA-verified.

## Callback wire contract

POST to an operator-registered HTTPS endpoint. The service signs the exact JSON message bytes with Ed25519, using `X-SecondFactor-Key-ID` and `X-SecondFactor-Signature` (unpadded base64url). Messages contain version, random request ID, application, operation, issued_at, and payload. Reject signatures from unregistered keys, wrong applications, stale messages, and unknown operations.

Operations: `session.verify`, `recovery.authorize`, and `sessions.revoke`. The public `integration.CallbackHandler` implements signature validation and response signing. Its underlying policy/session implementations remain your responsibility.

Responses are signed using the application's registered key and contain the original ID/application/operation plus the typed result. The service checks this correlation. Revocation is idempotent by persisted job ID, independent of transport-request IDs. Policy authorizers must also handle retries safely. Protect callback endpoints with private networking or mTLS where possible.

The demo authorizer denies assisted recovery. Integrators must supply their own policy; the example does not pretend that mock login proves identity for account recovery.
