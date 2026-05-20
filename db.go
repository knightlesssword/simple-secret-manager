package main

import (
	"database/sql"
	"fmt"

	// The underscore import registers the modernc SQLite driver with database/sql.
	// After this, sql.Open("sqlite", ...) works.
	_ "modernc.org/sqlite"
)

// openDB opens (or creates) ./secrets.db and ensures the required tables exist.
// Returns a *sql.DB handle the caller is responsible for closing.
func openDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "./secrets.db")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Verify the connection is actually alive (sql.Open is lazy).
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	if err := createTables(db); err != nil {
		return nil, err
	}

	return db, nil
}

// createTables creates the two tables we need if they don't already exist.
// SQLite executes CREATE TABLE IF NOT EXISTS as a no-op on subsequent runs,
// so it's safe to call every time the program starts.
func createTables(db *sql.DB) error {
	// secrets — main storage: one row per key/value pair.
	// The value column is BLOB because we store raw encrypted bytes, not text.
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			key   TEXT NOT NULL PRIMARY KEY,
			value BLOB NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create secrets table: %w", err)
	}

	// meta — single-row config table.
	// We use it to store the Argon2id salt so it's consistent across runs.
	// Without a stable salt, the same password would produce a different key
	// each time, making previously stored secrets unreadable.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS meta (
			key   TEXT NOT NULL PRIMARY KEY,
			value BLOB NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("create meta table: %w", err)
	}

	return nil
}
