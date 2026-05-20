package main

import (
	"fmt"
	"os"
)

func main() {
	// os.Args[0] is the binary name; os.Args[1] is the subcommand (if given)
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Open (or create) the database first — all commands need it.
	db, err := openDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error opening database:", err)
		os.Exit(1)
	}
	defer db.Close()

	// list doesn't need to decrypt anything, so we only derive the master key
	// for the commands that actually read or write secret values.
	cmd := os.Args[1]
	args := os.Args[2:] // everything after the subcommand name

	if cmd == "list" {
		cmdList(db)
		return
	}

	// All other commands need the encryption key derived from the master password.
	key, err := masterKey(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	switch cmd {
	case "set":
		cmdSet(db, key, args)
	case "get":
		cmdGet(db, key, args)
	case "delete":
		cmdDelete(db, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`simple-secretmanager — a tiny local secrets store

Usage:
  secrets set   <KEY> <VALUE>   store or overwrite a secret
  secrets get   <KEY>           retrieve a secret
  secrets list                  list all key names
  secrets delete <KEY>          remove a secret

Environment:
  SECRETS_MASTER_PW   master password used to encrypt/decrypt secrets`)
}
