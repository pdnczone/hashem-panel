package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 default HMAC-SHA1, required by authenticator apps
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Optional TOTP two-factor login (RFC 6238: SHA-1, 6 digits, 30 s step).
// Off by default. When enabled, a correct password alone no longer opens a
// session; a valid code or a one-time recovery code is also required.

const (
	totpStep      = 30
	totpDigits    = 6
	totpSkew      = 1 // accept previous/next step for clock drift
	recoveryCount = 8
)

// timeNow is swappable so tests control the clock.
var timeNow = time.Now

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var (
	totpMu       sync.Mutex
	totpLastStep int64 // replay guard: a step may be used once
)

func newTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return b32.EncodeToString(b)
}

// totpAt computes the code for a given unix time.
func totpAt(secret string, unix int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(unix/totpStep))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, v%mod), nil
}

// verifyTOTP checks code against secret near now. consume=true records the
// matched step so the same code cannot be replayed.
func verifyTOTP(secret, code string, now time.Time, consume bool) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	totpMu.Lock()
	defer totpMu.Unlock()
	cur := now.Unix() / totpStep
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := cur + d
		want, err := totpAt(secret, step*totpStep)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			if step <= totpLastStep {
				return false // replay
			}
			if consume {
				totpLastStep = step
			}
			return true
		}
	}
	return false
}

func totpURI(secret, account, issuer string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpStep))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}

func hashRecovery(code string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))))
	return hex.EncodeToString(h[:])
}

// newRecoveryCodes returns plaintext codes (shown once) and their hashes.
func newRecoveryCodes() (plain, hashed []string) {
	for i := 0; i < recoveryCount; i++ {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			panic("crypto/rand unavailable: " + err.Error())
		}
		h := hex.EncodeToString(b) // 10 hex chars
		c := h[:5] + "-" + h[5:]
		plain = append(plain, c)
		hashed = append(hashed, hashRecovery(c))
	}
	return
}

// useRecoveryCode consumes a matching one-time code; caller holds mu and saves cfg.
func useRecoveryCode(code string) bool {
	h := hashRecovery(code)
	for i, x := range cfg.RecoveryHashes {
		if subtle.ConstantTimeCompare([]byte(x), []byte(h)) == 1 {
			cfg.RecoveryHashes = append(cfg.RecoveryHashes[:i:i], cfg.RecoveryHashes[i+1:]...)
			return true
		}
	}
	return false
}

// checkSecondFactor validates a login's second factor (TOTP or recovery code).
func checkSecondFactor(code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	if verifyTOTP(cfg.TOTPSecret, code, timeNow(), true) {
		return true
	}
	mu.Lock()
	defer mu.Unlock()
	if useRecoveryCode(code) {
		saveCfg()
		return true
	}
	return false
}
