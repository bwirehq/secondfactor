package integration

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresReplayGuardSingleUse(t *testing.T) {
	dsn := os.Getenv("SECONDFACTOR_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("SF_REQUIRE_DB") == "1" {
			t.Fatal("SECONDFACTOR_TEST_DATABASE_URL required")
		}
		t.Skip("PostgreSQL test database not configured")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "sf_callback_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = MigrateCallbackReplays(ctx, pool); err != nil {
		t.Fatal(err)
	}
	g := PostgresReplayGuard{Pool: pool}
	var success atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := g.Consume(ctx, "app", "request-id-1234567890", time.Now().Add(time.Minute))
			if e != nil {
				t.Error(e)
			} else if ok {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("expected one callback execution, got %d", success.Load())
	}
	// A separate application must not share a replay namespace.
	if ok, e := g.Consume(ctx, "other", "request-id-1234567890", time.Now().Add(time.Minute)); e != nil || !ok {
		t.Fatalf("tenant replay namespace failed: %v", e)
	}
	if _, e := pool.Exec(ctx, "UPDATE secondfactor_callback_replays SET expires_at=clock_timestamp()-interval '1 second'"); e != nil {
		t.Fatal(e)
	}
	if e := CleanupCallbackReplays(ctx, pool, 100); e != nil {
		t.Fatal(e)
	}
	if ok, e := g.Consume(ctx, "app", "request-id-1234567890", time.Now().Add(time.Minute)); e != nil || !ok {
		t.Fatalf("expired replay record not cleaned: %v", e)
	}
	if ok, e := (PostgresReplayGuard{}).Consume(ctx, "app", "id", time.Now().Add(time.Minute)); e == nil || ok {
		t.Fatal("missing replay storage did not fail closed")
	}
}
