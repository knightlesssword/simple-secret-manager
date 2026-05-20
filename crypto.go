package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

// Argon2id tuning parameters.
// These balance security vs. speed for a local CLI tool.
// time=1 iteration, 64 MB memory, 4 parallel threads → ~200ms on a modern machine.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // kilobytes (64 MB)
	argonThreads = 4
	argonKeyLen  = 32 // 32 bytes = 256-bit AES key
)

// masterKey reads SECRETS_MASTER_PW from the environment, loads (or generates)
// the Argon2id salt from the meta table, and returns a 32-byte derived key.
//
// The salt is generated once and saved to the DB on first run.
// On every subsequent run the same salt is loaded, so the same password
// always produces the same key — making stored secrets decryptable.
func masterKey(db *sql.DB) ([]byte, error) {
	pw := os.Getenv("SECRETS_MASTER_PW")
	if pw == "" {
		return nil, fmt.Errorf("SECRETS_MASTER_PW environment variable is not set")
	}

	salt, err := getOrCreateSalt(db)
	if err != nil {
		return nil, err
	}

	// argon2.IDKey is the Argon2id variant — resistant to GPU and side-channel attacks.
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return key, nil
}

// getOrCreateSalt loads the salt from the meta table.
// If it doesn't exist yet (first run), it generates 16 random bytes and saves them.
func getOrCreateSalt(db *sql.DB) ([]byte, error) {
	var salt []byte
	err := db.QueryRow(`SELECT value FROM meta WHERE key = 'argon2_salt'`).Scan(&salt)

	if err == sql.ErrNoRows {
		// First run: generate a cryptographically random 16-byte salt.
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
		_, err = db.Exec(`INSERT INTO meta (key, value) VALUES ('argon2_salt', ?)`, salt)
		if err != nil {
			return nil, fmt.Errorf("save salt: %w", err)
		}
		return salt, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load salt: %w", err)
	}

	return salt, nil
}

// encrypt encrypts plaintext using AES-256-GCM.
//
// GCM (Galois/Counter Mode) gives us both encryption AND authentication —
// if anyone tampers with the ciphertext, decryption will fail with an error
// rather than silently returning garbage.
//
// Layout of the returned bytes: [ 12-byte nonce | ciphertext+tag ]
// Prepending the nonce makes it easy to split off during decryption.
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// A nonce must be unique per encryption — never reuse a nonce with the same key.
	// 12 bytes is the standard GCM nonce size; random is the safest approach here.
	nonce := make([]byte, gcm.NonceSize()) // gcm.NonceSize() == 12
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal encrypts and appends a 16-byte authentication tag.
	// We prepend the nonce so decrypt() can pull it back out.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt reverses encrypt: splits off the nonce, then decrypts+verifies.
// Returns an error if the key is wrong or the ciphertext was tampered with.
func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split: first nonceSize bytes are the nonce, the rest is the actual ciphertext.
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// This fires if the key is wrong — don't leak details to the caller.
		return nil, fmt.Errorf("decryption failed (wrong password?)")
	}

	return plaintext, nil
}
