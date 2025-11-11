package storage

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Open opens an sqlite database using the provided DSN.
func Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

// Migrate applies all embedded SQL migrations in lexical order.
func Migrate(ctx context.Context, db *sql.DB) error {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, string(b)); err != nil {
			tx.Rollback()
			return fmt.Errorf("running migration %s: %w", entry.Name(), err)
		}
	}

	return tx.Commit()
}
