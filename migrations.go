package secondfactor

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate explicitly applies embedded schema migrations; New never applies migrations.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, e := pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(739121,1)`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS secondfactor_migrations(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); e != nil {
		return e
	}
	files, e := migrations.ReadDir("migrations")
	if e != nil {
		return e
	}
	for _, f := range files {
		raw, e := migrations.ReadFile("migrations/" + f.Name())
		if e != nil {
			return e
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		var stored string
		e = tx.QueryRow(ctx, `SELECT checksum FROM secondfactor_migrations WHERE version=$1`, f.Name()).Scan(&stored)
		if e == nil {
			if stored != digest {
				return fmt.Errorf("migration checksum mismatch: %s", f.Name())
			}
			continue
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if _, e = tx.Exec(ctx, string(raw)); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO secondfactor_migrations(version,checksum) VALUES($1,$2)`, f.Name(), digest); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

// RegisterApplications explicitly initializes application rows after migration.
func (s *Service) RegisterApplications(ctx context.Context) error {
	for id := range s.apps {
		if _, e := s.pool.Exec(ctx, `INSERT INTO secondfactor_applications(app_id) VALUES($1) ON CONFLICT DO NOTHING`, id); e != nil {
			return e
		}
	}
	return nil
}
