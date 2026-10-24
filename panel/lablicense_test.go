package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteLabLicense (only with LAB_LICENSE_DIR set) writes the public half
// of a throwaway signing key and a "pathtest" license signed with it, for the
// netns labs: they build gre-panel with
//
//	-ldflags "-X main.defaultMasterPublicKeyB64=$(cat $LAB_LICENSE_DIR/pub)"
//
// The private key is never written; a normal build never trusts this key.
func TestWriteLabLicense(t *testing.T) {
	dir := os.Getenv("LAB_LICENSE_DIR")
	if dir == "" {
		t.Skip("LAB_LICENSE_DIR not set")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	feats := []string{proPathTest}
	if f := os.Getenv("LAB_LICENSE_FEATURES"); f != "" { // e.g. "bagher" for a full Pro key
		feats = strings.Split(f, ",")
	}
	tok := generateTestToken(t, "lab", "*", feats, time.Now().Add(24*time.Hour).Unix(), priv)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pub"), []byte(base64.StdEncoding.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "license.key"), []byte(tok), 0600); err != nil {
		t.Fatal(err)
	}
}
