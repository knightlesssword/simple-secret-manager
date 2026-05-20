package main

import (
	"database/sql"
	"fmt"
	"os"
)

// cmdSet stores (or overwrites) a secret.
// Usage: secrets set <KEY> <VALUE>
func cmdSet(db *sql.DB, key []byte, args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: secrets set <KEY> <VALUE>")
		os.Exit(1)
	}

	name, value := args[0], args[1]

	// Encrypt the value before storing it.
	// The key column stays plaintext — only values are sensitive.
	encrypted, err := encrypt(key, []byte(value))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error encrypting:", err)
		os.Exit(1)
	}

	// INSERT OR REPLACE handles both new keys and updates to existing ones.
	_, err = db.Exec(`INSERT OR REPLACE INTO secrets (key, value) VALUES (?, ?)`, name, encrypted)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error saving secret:", err)
		os.Exit(1)
	}

	fmt.Printf("stored: %s\n", name)
}

// cmdGet retrieves and decrypts a single secret by key.
// Usage: secrets get <KEY>
func cmdGet(db *sql.DB, key []byte, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secrets get <KEY>")
		os.Exit(1)
	}

	name := args[0]

	var encrypted []byte
	err := db.QueryRow(`SELECT value FROM secrets WHERE key = ?`, name).Scan(&encrypted)
	if err == sql.ErrNoRows {
		fmt.Fprintf(os.Stderr, "not found: %s\n", name)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading secret:", err)
		os.Exit(1)
	}

	plaintext, err := decrypt(key, encrypted)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error decrypting:", err)
		os.Exit(1)
	}

	// Print the value to stdout so it can be captured by scripts: $(secrets get KEY)
	fmt.Println(string(plaintext))
}

// cmdList prints all stored key names without revealing their values.
// Usage: secrets list
func cmdList(db *sql.DB) {
	rows, err := db.Query(`SELECT key FROM secrets ORDER BY key`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error listing secrets:", err)
		os.Exit(1)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			fmt.Fprintln(os.Stderr, "error reading row:", err)
			os.Exit(1)
		}
		fmt.Println(name)
		count++
	}

	// rows.Err() catches any error that occurred during iteration.
	if err := rows.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "iteration error:", err)
		os.Exit(1)
	}

	if count == 0 {
		fmt.Println("(no secrets stored)")
	}
}

// cmdDelete removes a secret by key.
// Usage: secrets delete <KEY>
func cmdDelete(db *sql.DB, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: secrets delete <KEY>")
		os.Exit(1)
	}

	name := args[0]

	result, err := db.Exec(`DELETE FROM secrets WHERE key = ?`, name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error deleting secret:", err)
		os.Exit(1)
	}

	// RowsAffected tells us whether the key actually existed.
	affected, _ := result.RowsAffected()
	if affected == 0 {
		fmt.Fprintf(os.Stderr, "not found: %s\n", name)
		os.Exit(1)
	}

	fmt.Printf("deleted: %s\n", name)
}
