// Package knowledgetest opens the knowledge database for tests.
package knowledgetest

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Open connects to the knowledge database in read-only mode, or skips the test when it is unreachable.
// PG_DB_HOST, PG_DB_PORT, PG_DB_USER and PG_DB_PASSWORD override the dev defaults (Postgres published on 127.0.0.1:5432).
func Open(t testing.TB) *bun.DB {
	t.Helper()
	dsn := dbhelper.BuildDSN(
		envOr("PG_DB_USER", "postgres"),
		envOr("PG_DB_PASSWORD", "!ChangeMe!"),
		envOr("PG_DB_HOST", "127.0.0.1"),
		envOr("PG_DB_PORT", "5432"),
		dbhelper.Config.Database.Knowledge,
	)
	// Read-only so tests can never change the knowledge data they run against.
	sqldb := sql.OpenDB(pgdriver.NewConnector(
		pgdriver.WithDSN(dsn),
		pgdriver.WithConnParams(map[string]any{"default_transaction_read_only": "on"}),
	))
	db := bun.NewDB(sqldb, pgdialect.New())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("knowledge database not reachable: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
