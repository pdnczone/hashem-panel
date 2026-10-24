package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

// SecureRandomHex generates n cryptographically secure random bytes
// and returns them as a hexadecimal string.
func SecureRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SecureRandomPassword generates a high-entropy password of the given length
// (minimum 16 chars) containing uppercase, lowercase, numbers, and special symbols.
func SecureRandomPassword(length int) string {
	if length < 16 {
		length = 16
	}
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghijkmnopqrstuvwxyz"
		digits  = "23456789"
		symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
		all     = upper + lower + digits + symbols
	)

	// Ensure at least 2 of each required class
	mustHave := []string{upper, upper, lower, lower, digits, digits, symbols, symbols}
	result := make([]byte, 0, length)

	for _, charset := range mustHave {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result = append(result, charset[idx.Int64()])
	}

	for len(result) < length {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(all))))
		result = append(result, all[idx.Int64()])
	}

	// Fisher-Yates shuffle using crypto/rand
	for i := len(result) - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(jBig.Int64())
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// ConstantTimeCompare compares two strings in constant time to prevent timing attacks.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ComputeSHA256 computes the SHA256 hash of data read from r.
func ComputeSHA256(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyFileSHA256 checks whether the file at path matches expectedHash (hex).
func VerifyFileSHA256(path, expectedHash string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	actual, err := ComputeSHA256(f)
	if err != nil {
		return err
	}

	if !strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expectedHash)) {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedHash, actual)
	}
	return nil
}

// ParseChecksumManifest parses standard SHA256SUMS or checksums.txt lines:
// "<sha256>  <filename>" or "<sha256> *<filename>".
func ParseChecksumManifest(manifest string) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(manifest))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && len(parts[0]) == 64 {
			hash := strings.ToLower(parts[0])
			filename := strings.TrimPrefix(parts[1], "*")
			result[filename] = hash
			result[filepathBase(filename)] = hash
		}
	}
	return result
}

func filepathBase(path string) string {
	idx := strings.LastIndexAny(path, "/\\")
	if idx >= 0 {
		return path[idx+1:]
	}
	return path
}
