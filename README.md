# simple-secretmanager

A minimal CLI secrets manager written in Go, backed by SQLite. Built as a v1/POC to understand the fundamentals of secret storage with encryption at rest.

## How it works

Secrets are stored as key/value pairs in a local SQLite database (`./secrets.db`). Each value is encrypted with AES-256-GCM. The encryption key is derived from a master password using Argon2id.

```
Master Password ──→ Argon2id ──→ 32-byte AES key ──→ AES-256-GCM encrypt/decrypt ──→ SQLite
```

The Argon2id salt is generated once on first run and stored in the DB. This ensures the same password always produces the same key across runs.

## Build

```powershell
go build -o secrets.exe .
```

## Usage

Set your master password as an environment variable before running:

```powershell
$env:SECRETS_MASTER_PW = "your-master-password"
```

### Commands

```powershell
# Store a secret
.\secrets.exe set DATABASE_URL "postgres://user:pass@host/db"

# Retrieve a secret
.\secrets.exe get DATABASE_URL

# List all stored key names (values are NOT shown)
.\secrets.exe list

# Delete a secret
.\secrets.exe delete DATABASE_URL
```

## Project structure

| File | Purpose |
|---|---|
| `main.go` | Entry point — opens DB, derives key, dispatches subcommands |
| `db.go` | Opens `./secrets.db`, creates `secrets` + `meta` tables |
| `crypto.go` | Argon2id key derivation, AES-256-GCM encrypt/decrypt |
| `commands.go` | `set`, `get`, `list`, `delete` implementations |

## Database

The database file `secrets.db` is created in the current working directory on first run. Keep it safe — without the master password, the contents cannot be decrypted.

## Dependencies

- [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) — pure-Go SQLite driver (no CGO required)
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — Argon2id and AES-GCM support

## What this is NOT

- Not a production secrets manager (no access control, no audit log, no multi-user support)
- Not a replacement for Vault, AWS Secrets Manager, etc.
- A learning POC to understand the building blocks
