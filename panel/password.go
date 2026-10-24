package main

// Password hashing (M-03). New hashes are argon2id with a random salt:
//
//	argon2id$v=19$m=19456,t=2,p=1$<salt b64>$<hash b64>
//
// Legacy panel.json files (and hashem.sh, which still writes them) hold an
// unsalted 64-char hex SHA-256. Those keep working and are transparently
// upgraded to argon2id on the next successful login or password change.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemKiB  = 19456 // 19 MiB (OWASP minimum recommendation)
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
	argonPrefix  = "argon2id$"
)

func hashPassword(pw string) string {
	// verifyPassword trims its input, so hash the same form or a password
	// with leading/trailing spaces could never log in.
	pw = strings.TrimSpace(pw)
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("%sv=%d$m=%d,t=%d,p=%d$%s$%s", argonPrefix, argon2.Version,
		argonMemKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func isLegacyHash(stored string) bool {
	stored = strings.TrimSpace(stored)
	if len(stored) != 64 {
		return false
	}
	_, err := hex.DecodeString(stored)
	return err == nil
}

// looksHashed reports whether stored is a password hash rather than a legacy
// plaintext password. A hash must never be accepted as the password itself.
func looksHashed(stored string) bool {
	return isLegacyHash(stored) ||
		strings.HasPrefix(stored, argonPrefix) ||
		strings.HasPrefix(stored, "$")
}

// verifyPassword reports whether pw matches stored, and whether stored is in a
// legacy format that should be re-hashed.
func verifyPassword(stored, pw string) (ok, needsUpgrade bool) {
	stored = strings.TrimSpace(stored)
	pw = strings.TrimSpace(pw)
	if stored == "" || pw == "" {
		return false, false
	}

	// Plaintext fallback (legacy configs where the password was saved
	// unhashed, min 8 chars); upgraded to argon2id on this login. Skipped for
	// anything hash-shaped, or the hash itself would work as the password.
	if !looksHashed(stored) {
		return len(stored) >= 8 && subtle.ConstantTimeCompare([]byte(stored), []byte(pw)) == 1, true
	}

	if isLegacyHash(stored) {
		h := sha256.Sum256([]byte(pw))
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(strings.ToLower(stored))) == 1, true
	}

	// Support both standard "$argon2id$..." and internal "argon2id$..."
	argonStr := stored
	hadDollarPrefix := false
	if strings.HasPrefix(argonStr, "$") {
		argonStr = strings.TrimPrefix(argonStr, "$")
		hadDollarPrefix = true
	}

	if !strings.HasPrefix(argonStr, argonPrefix) {
		return false, false
	}
	parts := strings.Split(argonStr, "$")
	// argon2id, v=19, m=..,t=..,p=.., salt, hash
	if len(parts) != 5 {
		return false, false
	}
	var ver, m, t, p int
	if _, err := fmt.Sscanf(parts[1], "v=%d", &ver); err != nil || ver != argon2.Version {
		return false, false
	}
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, false
	}
	if m < 8 || m > 1<<20 || t < 1 || t > 10 || p < 1 || p > 16 {
		return false, false // refuse absurd parameters (DoS guard)
	}
	decodeB64 := func(s string) ([]byte, error) {
		s = strings.TrimRight(s, "=")
		return base64.RawStdEncoding.DecodeString(s)
	}
	salt, err1 := decodeB64(parts[3])
	want, err2 := decodeB64(parts[4])
	if err1 != nil || err2 != nil || len(want) == 0 || len(want) > 128 {
		return false, false
	}
	got := argon2.IDKey([]byte(pw), salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1,
		m < argonMemKiB || t < argonTime || hadDollarPrefix
}

// newSessionToken returns a random 256-bit session id (not derived from the
// password hash, so it cannot be recomputed from a leaked panel.json).
func newSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
