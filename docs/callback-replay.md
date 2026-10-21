# Callback replay and event-worker security

## Why both controls matter

Ed25519 signatures authenticate backend messages, but a captured signed message could still be presented a second time before it expires. The receiving application's callback endpoint must atomically reject duplicate request IDs. Separately, tenant-wide event delivery must not be accessible with an ordinary user-context signing key.

## Durable application callback replay guard

The `integration.CallbackHandler` requires `Replay CallbackReplayGuard`, with this interface:

```go
type CallbackReplayGuard interface {
    Consume(ctx context.Context, application, requestID string, expiresAt time.Time) (fresh bool, err error)
}
```

`Consume` must return `true` exactly once per application and request ID, `false` for duplicates, and an error if storage is unavailable. The operation must be atomic across application replicas and survive restarts. **Fail closed** if the guard is absent.

The integration package includes a concrete `PostgresReplayGuard`. Apply its schema **explicitly in your application database**:

```go
if err := integration.MigrateCallbackReplays(ctx, applicationPool); err != nil {
    return err
}
guard := integration.PostgresReplayGuard{Pool: applicationPool}
handler := &integration.CallbackHandler{
    Replay: guard,
    // Configure Application, ServiceKeys, PrivateKey,
    // Sessions, Recovery, and Revoker with trusted values.
}
```

The schema uses a unique `(application_id, request_id)` primary key. The guard uses one parameterized `INSERT ... ON CONFLICT DO NOTHING` instead of a race-prone check-then-insert. Schedule `integration.CleanupCallbackReplays(ctx, pool, 1000)` periodically to remove expired IDs. Never clear entries before the maximum message validity plus clock tolerance.

`integration.NewMemoryReplayGuard()` is only for the single-process local demo and tests. It is **not production safe** across multiple replicas or restarts.

## Privileged outbox credentials

Set `event_signing_keys` on the application in the SecondFactor service configuration. These keys are distinct from `signing_keys` and may call **only**:

- `POST /v1/events/claim`
- `POST /v1/events/ack`

Normal application keys cannot call those routes. Event keys cannot authenticate ordinary factor, proof or recovery requests. Missing worker keys disable event delivery rather than allowing a fallback to a normal application key.

Create an independent worker-only SDK client with the event key. Never ship a signing seed to the browser, proxy the event endpoints to user-facing routes, or log the recovery invitation `Delivery` field. Acknowledge an event only after successful secure delivery.

## Production checklist

- [ ] Durable, cross-replica callback replay guard configured
- [ ] Worker signing key material separate from ordinary application signing keys
- [ ] Worker-only network access and private key custody
- [ ] Authoritative primary session verification and durable session revocation
- [ ] Independent recovery authorization with verified evidence
- [ ] Recovery invitations transmitted privately, deduplicated and acknowledged
- [ ] Regression tests for duplicated callbacks and unauthorized event claims
- [ ] Independent security review before sensitive production use
