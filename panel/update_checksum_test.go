package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Regression (M-01): the updater used to install a binary whenever the checksum
// manifest was missing (fail-open). It must refuse unless explicitly opted out.
func TestVerifyAssetChecksumFailClosed(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bin")
	content := []byte("\x7fELF-fake-binary")
	if err := os.WriteFile(f, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	good := hex.EncodeToString(sum[:])
	old := manifestFetcher
	defer func() { manifestFetcher = old }()
	t.Setenv("GRE_PANEL_ALLOW_UNVERIFIED_UPDATE", "")

	// 1. manifest unavailable -> refuse
	manifestFetcher = func(string) (map[string]string, error) { return nil, os.ErrNotExist }
	if err := verifyAssetChecksum(f, "v1", "gre-panel-linux-amd64"); err == nil {
		t.Fatal("expected refusal when manifest is unavailable")
	}
	// 2. manifest present but asset missing -> refuse
	manifestFetcher = func(string) (map[string]string, error) { return map[string]string{"other": good}, nil }
	if err := verifyAssetChecksum(f, "v1", "gre-panel-linux-amd64"); err == nil {
		t.Fatal("expected refusal when asset entry is missing")
	}
	// 3. wrong hash -> refuse
	manifestFetcher = func(string) (map[string]string, error) {
		return map[string]string{"gre-panel-linux-amd64": hex.EncodeToString(make([]byte, 32))}, nil
	}
	if err := verifyAssetChecksum(f, "v1", "gre-panel-linux-amd64"); err == nil {
		t.Fatal("expected refusal on hash mismatch")
	}
	// 4. correct hash -> ok
	manifestFetcher = func(string) (map[string]string, error) { return map[string]string{"gre-panel-linux-amd64": good}, nil }
	if err := verifyAssetChecksum(f, "v1", "gre-panel-linux-amd64"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	// 5. explicit opt-out allows missing manifest
	manifestFetcher = func(string) (map[string]string, error) { return nil, os.ErrNotExist }
	t.Setenv("GRE_PANEL_ALLOW_UNVERIFIED_UPDATE", "1")
	if err := verifyAssetChecksum(f, "v1", "gre-panel-linux-amd64"); err != nil {
		t.Fatalf("opt-out should allow, got %v", err)
	}
}
