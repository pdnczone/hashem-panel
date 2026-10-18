package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper to generate a test signed license token
func generateTestToken(t *testing.T, customer, machineHash string, features []string, exp int64, privKey ed25519.PrivateKey) string {
	t.Helper()
	payload := LicensePayload{
		Customer:    customer,
		MachineHash: machineHash,
		Features:    features,
		ExpiresAt:   exp,
		IssuedAt:    time.Now().Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	sig := ed25519.Sign(privKey, data)
	return fmt.Sprintf("%s.%s", base64.RawURLEncoding.EncodeToString(data), base64.RawURLEncoding.EncodeToString(sig))
}

func TestLicenseVerificationAndFeatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating test keypair: %v", err)
	}

	origKey := masterPublicKeyB64
	masterPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	defer func() { masterPublicKeyB64 = origKey }()

	mHash := getMachineHash()

	// 1. Valid token with matching machine hash
	expFuture := time.Now().Add(24 * time.Hour).Unix()
	validToken := generateTestToken(t, "Alice", mHash, []string{"bagher", "watchdog"}, expFuture, priv)

	p, err := verifyLicenseKey(validToken)
	if err != nil {
		t.Fatalf("expected valid token, got err: %v", err)
	}
	if p.Customer != "Alice" || !HasFeatureString(p.Features, "bagher") {
		t.Errorf("payload mismatch: %+v", p)
	}

	// 2. Token with wildcard machine hash
	wildcardToken := generateTestToken(t, "Bob", "*", []string{"bagher"}, expFuture, priv)
	pWildcard, err := verifyLicenseKey(wildcardToken)
	if err != nil {
		t.Fatalf("wildcard token error: %v", err)
	}
	if pWildcard.Customer != "Bob" {
		t.Errorf("wildcard customer mismatch: %s", pWildcard.Customer)
	}

	// 3. Token with mismatched machine hash
	badMachineToken := generateTestToken(t, "Charlie", "deadbeef000011112222333344445555", []string{"bagher"}, expFuture, priv)
	if _, err := verifyLicenseKey(badMachineToken); err == nil {
		t.Fatalf("expected machine mismatch error, got nil")
	}

	// 4. Expired token
	expPast := time.Now().Add(-24 * time.Hour).Unix()
	expiredToken := generateTestToken(t, "Dave", mHash, []string{"bagher"}, expPast, priv)
	if _, err := verifyLicenseKey(expiredToken); err == nil {
		t.Fatalf("expected expired error, got nil")
	}

	// 5. Tampered token
	tamperedToken := validToken + "tamper"
	if _, err := verifyLicenseKey(tamperedToken); err == nil {
		t.Fatalf("expected signature verification failure, got nil")
	}

	// 6. Invalid format
	if _, err := verifyLicenseKey("invalid_token_without_dot"); err == nil {
		t.Fatalf("expected format error, got nil")
	}

	// 7. Multi-server / Comma-separated machine hash (e.g. 1 Iran + 1 Foreign)
	multiMachineToken := generateTestToken(t, "MultiServer", "otherhash1234,"+mHash+",thirdhash999", []string{"*"}, expFuture, priv)
	pMulti, err := verifyLicenseKey(multiMachineToken)
	if err != nil {
		t.Fatalf("expected multi-server token to be valid for current machine, got err: %v", err)
	}
	if pMulti.Customer != "MultiServer" {
		t.Errorf("multi-server customer mismatch: %s", pMulti.Customer)
	}

	// 8. Multi-server token with no match
	multiMismatchToken := generateTestToken(t, "MultiFail", "otherhash1234,thirdhash999", []string{"*"}, expFuture, priv)
	if _, err := verifyLicenseKey(multiMismatchToken); err == nil {
		t.Fatalf("expected multi-machine mismatch error, got nil")
	}
}

func HasFeatureString(features []string, f string) bool {
	for _, item := range features {
		if item == "*" || item == "all" || item == f {
			return true
		}
	}
	return false
}

func TestVerifyStoredTokens(t *testing.T) {
	data, err := os.ReadFile("/opt/hashem-licensor/licenses.db")
	if err != nil {
		t.Skip("no licensor db")
	}
	_ = data
	// Let's test with a freshly generated wildcard token using the master key
	keyData, err := os.ReadFile("/root/.hashem-license/master.key")
	if err != nil {
		t.Fatalf("cannot read master key: %v", err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
	if err != nil {
		t.Fatalf("invalid privBytes: %v", err)
	}
	priv := ed25519.PrivateKey(privBytes)
	wildcardToken := generateTestToken(t, "FullAdmin", "*", []string{"bagher", "frp_ssh", "watchdog"}, time.Now().Add(365*24*time.Hour).Unix(), priv)
	p, err := verifyLicenseKey(wildcardToken)
	t.Logf("Wildcard token err=%v, payload=%+v", err, p)
	if err != nil {
		t.Fatalf("wildcard failed: %v", err)
	}
}

func TestLicenseAPI(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating test keypair: %v", err)
	}

	origKey := masterPublicKeyB64
	masterPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	defer func() {
		masterPublicKeyB64 = origKey
		activeLicenseMu.Lock()
		activeLicense = nil
		licenseCheckedAt = time.Now()
		activeLicenseMu.Unlock()
		_ = os.Remove("/etc/hashem/license.key")
		_ = os.Remove(filepath.Join(configDir, "license.key"))
	}()

	mHash := getMachineHash()
	expFuture := time.Now().Add(48 * time.Hour).Unix()
	validToken := generateTestToken(t, "VIP_User", mHash, []string{"bagher"}, expFuture, priv)

	// POST /api/license to activate
	body, _ := json.Marshal(map[string]string{"key": validToken})
	reqPost := httptest.NewRequest("POST", "/api/license", bytes.NewReader(body))
	rrPost := httptest.NewRecorder()
	handleLicensePost(rrPost, reqPost)
	if rrPost.Code != http.StatusOK {
		t.Fatalf("POST /api/license failed with code %d: %s", rrPost.Code, rrPost.Body.String())
	}

	if !HasFeature("bagher") {
		t.Errorf("expected HasFeature(bagher) == true after activation")
	}

	// GET /api/license
	reqGet := httptest.NewRequest("GET", "/api/license", nil)
	rrGet := httptest.NewRecorder()
	handleLicenseGet(rrGet, reqGet)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET /api/license failed: %d", rrGet.Code)
	}

	var status map[string]any
	if err := json.NewDecoder(rrGet.Body).Decode(&status); err != nil {
		t.Fatalf("decode GET status err: %v", err)
	}
	if status["is_valid"] != true || status["customer"] != "VIP_User" {
		t.Errorf("license status mismatch: %+v", status)
	}
}

func TestDualKeyVerification(t *testing.T) {
	// Key 1: simulates legacy master key (e.g., v2.3.4)
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key 1: %v", err)
	}

	// Key 2: simulates new master key (e.g., dedicated licensor)
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key 2: %v", err)
	}

	// Key 3: untrusted / rogue key
	_, priv3, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key 3: %v", err)
	}

	origMaster := masterPublicKeyB64
	origTrusted := trustedMasterPublicKeysB64
	masterPublicKeyB64 = base64.StdEncoding.EncodeToString(pub2)
	trustedMasterPublicKeysB64 = []string{
		base64.StdEncoding.EncodeToString(pub2),
		base64.StdEncoding.EncodeToString(pub1),
	}
	defer func() {
		masterPublicKeyB64 = origMaster
		trustedMasterPublicKeysB64 = origTrusted
		activeLicenseMu.Lock()
		activeLicense = nil
		licenseCheckedAt = time.Now()
		activeLicenseMu.Unlock()
		_ = os.Remove(filepath.Join(configDir, "license.key"))
		_ = os.Remove("/etc/hashem/license.key")
	}()

	mHash := getMachineHash()
	expFuture := time.Now().Add(30 * 24 * time.Hour).Unix()

	// 1. Token signed with legacy key (Key 1)
	legacyToken := generateTestToken(t, "LegacyCustomer", mHash, []string{"legacy_feature"}, expFuture, priv1)
	p1, err := verifyLicenseKey(legacyToken)
	if err != nil {
		t.Fatalf("legacy token failed verification: %v", err)
	}
	if p1.Customer != "LegacyCustomer" {
		t.Errorf("legacy customer mismatch: %s", p1.Customer)
	}

	// 2. Token signed with new key (Key 2)
	newToken := generateTestToken(t, "NewCustomer", mHash, []string{"new_feature"}, expFuture, priv2)
	p2, err := verifyLicenseKey(newToken)
	if err != nil {
		t.Fatalf("new token failed verification: %v", err)
	}
	if p2.Customer != "NewCustomer" {
		t.Errorf("new customer mismatch: %s", p2.Customer)
	}

	// 3. Token signed with untrusted key (Key 3)
	untrustedToken := generateTestToken(t, "Attacker", mHash, []string{"hack"}, expFuture, priv3)
	if _, err := verifyLicenseKey(untrustedToken); err == nil {
		t.Fatalf("expected untrusted token to fail verification, but it succeeded")
	}

	// 4. Test loading existing legacy license from disk (simulating upgrade)
	_ = os.MkdirAll(configDir, 0755)
	if err := os.WriteFile(filepath.Join(configDir, "license.key"), []byte(legacyToken), 0600); err != nil {
		t.Fatalf("failed writing legacy license file: %v", err)
	}
	loadLicenseFromDisk()
	if !HasFeature("legacy_feature") {
		t.Errorf("expected legacy_feature to be active after loading from disk upon upgrade")
	}

	// 5. Test activating new token via API
	body, _ := json.Marshal(map[string]string{"key": newToken})
	reqPost := httptest.NewRequest("POST", "/api/license", bytes.NewReader(body))
	rrPost := httptest.NewRecorder()
	handleLicensePost(rrPost, reqPost)
	if rrPost.Code != http.StatusOK {
		t.Fatalf("failed activating new token via API: %d %s", rrPost.Code, rrPost.Body.String())
	}
	if !HasFeature("new_feature") {
		t.Errorf("expected new_feature to be active after activating new token")
	}

	// 6. Test activating legacy token via API
	bodyLegacy, _ := json.Marshal(map[string]string{"key": legacyToken})
	reqPostLegacy := httptest.NewRequest("POST", "/api/license", bytes.NewReader(bodyLegacy))
	rrPostLegacy := httptest.NewRecorder()
	handleLicensePost(rrPostLegacy, reqPostLegacy)
	if rrPostLegacy.Code != http.StatusOK {
		t.Fatalf("failed activating legacy token via API: %d %s", rrPostLegacy.Code, rrPostLegacy.Body.String())
	}
	if !HasFeature("legacy_feature") {
		t.Errorf("expected legacy_feature to be active after activating legacy token")
	}

	// 7. Test activating untrusted token via API (must fail with 400 Bad Request)
	bodyUntrusted, _ := json.Marshal(map[string]string{"key": untrustedToken})
	reqPostUntrusted := httptest.NewRequest("POST", "/api/license", bytes.NewReader(bodyUntrusted))
	rrPostUntrusted := httptest.NewRecorder()
	handleLicensePost(rrPostUntrusted, reqPostUntrusted)
	if rrPostUntrusted.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for untrusted token, got %d", rrPostUntrusted.Code)
	}
}

// withTestLicense installs a throwaway signing key, an empty configDir and a
// valid license.key, and restores the globals afterwards.
func withTestLicense(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldMaster, oldTrusted := masterPublicKeyB64, trustedMasterPublicKeysB64
	oldDir, oldCfg, oldLoaded := configDir, cfg, cfgLoaded.Load()
	masterPublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	trustedMasterPublicKeysB64 = nil
	configDir = t.TempDir()
	t.Cleanup(func() {
		masterPublicKeyB64, trustedMasterPublicKeysB64 = oldMaster, oldTrusted
		configDir, cfg = oldDir, oldCfg
		cfgLoaded.Store(oldLoaded)
		licenseKeyCleared.Store(false)
		_ = os.Remove("/etc/hashem/license.key")
		activeLicenseMu.Lock()
		activeLicense = nil
		licenseCheckedAt = time.Now()
		activeLicenseMu.Unlock()
	})
	token := generateTestToken(t, "C1", getMachineHash(), []string{"cluster"}, time.Now().Add(time.Hour).Unix(), priv)
	if err := os.WriteFile(filepath.Join(configDir, "license.key"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	return token
}

func readPanelJSON(t *testing.T) panelConfig {
	t.Helper()
	data, err := os.ReadFile(cfgPath())
	if err != nil {
		t.Fatal(err)
	}
	var c panelConfig
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// C1: loading the license before loadOrInit() must not save the zero-value
// cfg over panel.json (it used to wipe 2FA on every restart).
func TestLicenseLoadKeepsPanelSettings(t *testing.T) {
	token := withTestLicense(t)
	cfg = panelConfig{Username: "admin", PassHash: hashPassword("Secret-123"), Port: 7777, BasePath: "p",
		TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP", TerminalEnabled: true}
	saveCfg()

	cfg = panelConfig{} // state before loadOrInit
	cfgLoaded.Store(false)
	loadLicenseFromDisk()
	if c := readPanelJSON(t); !c.TOTPEnabled || c.TOTPSecret == "" || !c.TerminalEnabled {
		t.Fatalf("panel.json settings wiped before config load: %+v", c)
	}

	loadOrInit()
	loadLicenseFromDisk()
	c := readPanelJSON(t)
	if !c.TOTPEnabled || !c.TerminalEnabled {
		t.Fatalf("panel.json settings wiped after license load: %+v", c)
	}
	if c.LicenseKey != token {
		t.Fatalf("license key not persisted to panel.json")
	}
	if !HasFeature("cluster") {
		t.Fatal("license not active")
	}
}

// H10: deactivation must clear panel.json too, or the key comes back.
func TestLicenseDeactivatePersists(t *testing.T) {
	withTestLicense(t)
	cfg = panelConfig{Username: "admin", PassHash: hashPassword("Secret-123"), Port: 7777, BasePath: "p"}
	saveCfg()
	cfgLoaded.Store(true)
	loadLicenseFromDisk()
	if readPanelJSON(t).LicenseKey == "" {
		t.Fatal("setup: license key not in panel.json")
	}

	rr := httptest.NewRecorder()
	handleLicensePost(rr, httptest.NewRequest("POST", "/api/license", strings.NewReader(`{"key":""}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("deactivate: %d %s", rr.Code, rr.Body.String())
	}
	if k := readPanelJSON(t).LicenseKey; k != "" {
		t.Fatal("license key still in panel.json after deactivation")
	}
	activeLicenseMu.Lock()
	licenseCheckedAt = time.Time{}
	activeLicenseMu.Unlock()
	if HasFeature("cluster") {
		t.Fatal("license re-activated from disk after deactivation")
	}
}
