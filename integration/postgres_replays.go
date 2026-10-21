package integration

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresReplayGuard provides a durable callback replay guard shared by every
// application instance using the same database. MigrateCallbackReplays is
// intentionally explicit; this type never applies schema changes itself.
type PostgresReplayGuard struct {
	Pool *pgxpool.Pool
}

// MigrateCallbackReplays explicitly creates the receiver application's
// replay table. Apply this in the consuming application's database.
func MigrateCallbackReplays(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("callback replay database is required")
	}
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS secondfactor_callback_replays (
		application_id text NOT NULL,
		request_id text NOT NULL,
		expires_at timestamptz NOT NULL,
		PRIMARY KEY (application_id,request_id)
	)`)
	return err
}

// Consume atomically rejects a callback ID after its first successful insert.
// Do not delete unexpired entries or use separate read-then-write operations.
func (g PostgresReplayGuard) Consume(ctx context.Context, application, requestID string, expiry time.Time) (bool, error) {
	if g.Pool == nil || application == "" || requestID == "" || !expiry.After(time.Now()) {
		return false, errors.New("callback replay storage or request is invalid")
	}
	tag, err := g.Pool.Exec(ctx, `INSERT INTO secondfactor_callback_replays(application_id,request_id,expires_at)
		VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, application, requestID, expiry)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// CleanupCallbackReplays deletes only expired callback IDs in bounded batches.
// Run it periodically using the consuming application's scheduled maintenance.
func CleanupCallbackReplays(ctx context.Context, pool *pgxpool.Pool, limit int) error {
	if pool == nil || limit < 1 || limit > 10000 {
		return errors.New("invalid callback replay cleanup configuration")
	}
	_, err := pool.Exec(ctx, `DELETE FROM secondfactor_callback_replays WHERE ctid IN
		(SELECT ctid FROM secondfactor_callback_replays
		 WHERE expires_at < clock_timestamp() LIMIT $1)`, limit)
	return err
}
