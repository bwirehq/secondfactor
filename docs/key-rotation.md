# Key rotation

Keep encryption keys outside PostgreSQL, backed up separately under appropriate access controls. `secondfactor keygen --dir new-directory` generates new keys without overwriting existing files. A key-generation directory also contains Ed25519 seeds; only the encryption key belongs in the encryption keyring.

1. Provision a new 32-byte encryption key with a new key ID.
2. Keep old keys in `encryption_keys` and set `active_key_id` to the new ID.
3. Restart all replicas with the complete keyring. New ciphertext uses the active key.
4. Run `secondfactor rotate --config config.json` until complete.
5. Run `secondfactor key-usage --config config.json` and verify no remaining reference to the old key.
6. Retire the old key only after every replica has switched and retained encrypted events are re-encrypted or deleted.

`CheckKeyCoverage` fails startup if persisted ciphertext references missing keys. Do not bypass it in embedded startup. Rotation preserves associated-data identity/purpose/encryption-version fields and does not invalidate MFA proofs merely to rotate encryption.

Use a rolling-deployment plan that prevents old replicas continuing to write with a retired key. Keep old decryption keys until those writers have stopped and final usage is zero.

Signing rotation is separate: register a new public key ID, switch signers, wait beyond assertion expiry and callback deadlines, then remove the old public key. Service callback keys and application assertion keys are separate.

Database restoration can restore consumed codes and old proof/replay state. After a restore, keep service traffic blocked, revoke primary sessions through the application, invalidate all MFA proofs/grants/enrollments, rotate recovery codes through a supported recovery policy, and reconcile assisted-recovery jobs before reopening traffic. Backups must be encrypted; losing all encryption keys makes factors unrecoverable without independent account recovery.
