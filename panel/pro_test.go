package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setTestLicense puts a license in memory only (nil: none) for one test.
func setTestLicense(t *testing.T, lic *LicensePayload) {
	t.Helper()
	oldDir := configDir
	configDir = t.TempDir() // no key on disk to fall back to
	activeLicenseMu.Lock()
	prev, prevAt := activeLicense, licenseCheckedAt
	activeLicense, licenseCheckedAt = lic, time.Now()
	activeLicenseMu.Unlock()
	t.Cleanup(func() {
		configDir = oldDir
		activeLicenseMu.Lock()
		activeLicense, licenseCheckedAt = prev, prevAt
		activeLicenseMu.Unlock()
	})
}

// withPro gives a test the license a Hashem Pro customer has: a Bagher key.
func withPro(t *testing.T) {
	t.Helper()
	setTestLicense(t, &LicensePayload{Customer: "test", Features: []string{"bagher"}})
}

// Keys issued before the path test, Backhaul and Diagnostics became Pro unlock
// them without a new key; add-ons that are not Pro (Sentinel, Cluster) do not.
func TestProFeaturesForExistingKeys(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	for _, c := range []struct {
		name  string
		lic   *LicensePayload
		allow []string
	}{
		{"bagher key", &LicensePayload{Features: []string{"bagher"}}, proFeatures},
		{"frp_ssh key", &LicensePayload{Features: []string{"frp_ssh"}}, proFeatures},
		{"star key", &LicensePayload{Features: []string{"*"}}, proFeatures},
		{"all key", &LicensePayload{Features: []string{"all"}}, proFeatures},
		{"key without a feature list", &LicensePayload{}, proFeatures},
		{"pathtest-only key", &LicensePayload{Features: []string{"pathtest"}}, []string{proPathTest}},
		{"sentinel add-on only", &LicensePayload{Features: []string{"sentinel"}}, nil},
		{"cluster add-on only", &LicensePayload{Features: []string{"cluster"}}, nil},
		{"expired bagher key", &LicensePayload{Features: []string{"bagher"}, ExpiresAt: past}, nil},
		{"no license", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			setTestLicense(t, c.lic)
			for _, f := range proFeatures {
				want := false
				for _, a := range c.allow {
					want = want || a == f
				}
				if got := hasPro(f); got != want {
					t.Errorf("%s: hasPro=%v, want %v", f, got, want)
				}
			}
		})
	}
}

func apiCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Code string `json:"error_code"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	return e.Code
}

func TestProGatesAPIs(t *testing.T) {
	calls := []struct {
		name string
		run  func() *httptest.ResponseRecorder
	}{
		{"path test start", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handlePathTestPost(rr, httptest.NewRequest("POST", "/api/pathtest", strings.NewReader(`{"action":"start","base_port":1}`)))
			return rr
		}},
		{"path test join", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handlePathTestPost(rr, httptest.NewRequest("POST", "/api/pathtest", strings.NewReader(`{"action":"join","code":"x"}`)))
			return rr
		}},
		{"diagnostics read", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleDoctorGet(rr, httptest.NewRequest("GET", "/api/doctor", nil))
			return rr
		}},
		{"diagnostics run", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleDoctorPost(rr, httptest.NewRequest("POST", "/api/doctor", strings.NewReader(`{"action":"nope"}`)))
			return rr
		}},
		{"performance read", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handlePerfGet(rr, httptest.NewRequest("GET", "/api/perf", nil))
			return rr
		}},
		{"performance change", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handlePerfPost(rr, httptest.NewRequest("POST", "/api/perf", strings.NewReader(`{"action":"nope"}`)))
			return rr
		}},
		{"watchdog read", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleWatchdogGet(rr, httptest.NewRequest("GET", "/api/watchdog", nil))
			return rr
		}},
		{"watchdog change", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleWatchdogPost(rr, httptest.NewRequest("POST", "/api/watchdog", strings.NewReader(`{"action":"nope"}`)))
			return rr
		}},
		{"backup download", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleBackupDownload(rr, httptest.NewRequest("GET", "/api/watchdog/backup-download?f=x", nil))
			return rr
		}},
		{"benchmark read", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleBenchmarkGet(rr, httptest.NewRequest("GET", "/api/benchmark", nil))
			return rr
		}},
		{"benchmark run", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleBenchmarkRun(rr, httptest.NewRequest("POST", "/api/benchmark/run", strings.NewReader(`{`)))
			return rr
		}},
		{"benchmark auto-pilot", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleBenchmarkAutoPilot(rr, httptest.NewRequest("POST", "/api/benchmark/autopilot", strings.NewReader(`{`)))
			return rr
		}},
		{"Xray tunnel action", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleXrayPost(rr, httptest.NewRequest("POST", "/api/xray", strings.NewReader(`{"action":"nope"}`)))
			return rr
		}},
		{"Xray SNI test", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleXrayPost(rr, httptest.NewRequest("POST", "/api/xray", strings.NewReader(`{"action":"snitest"}`)))
			return rr
		}},
		{"speed and volume limits", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleLimitsPost(rr, httptest.NewRequest("POST", "/api/limits", strings.NewReader(`{"action":"nope"}`)))
			return rr
		}},
		{"Backhaul setup", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleSetupPost(rr, httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"role":"iran","engine":"backhaul","local_public":"bad"}`)))
			return rr
		}},
		{"Backhaul with GRE setup", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			handleSetupPost(rr, httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"role":"iran","engine":"gre-backhaul","local_public":"bad"}`)))
			return rr
		}},
	}
	t.Run("locked without a license", func(t *testing.T) {
		setTestLicense(t, nil)
		for _, c := range calls {
			if rr := c.run(); rr.Code != 403 || apiCode(t, rr) != "E-LIC-01" {
				t.Errorf("%s: %d %s", c.name, rr.Code, rr.Body.String())
			}
		}
		if !backhaulLocked("backhaul") || !backhaulLocked("gre-backhaul") || backhaulLocked("frp") {
			t.Error("engine switch to Backhaul is not locked")
		}
		// GRE + FRP setup stays free: it fails on the bad IP, not on the license
		rr := httptest.NewRecorder()
		handleSetupPost(rr, httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"role":"iran","engine":"frp","local_public":"bad"}`)))
		if apiCode(t, rr) == "E-LIC-01" {
			t.Error("GRE + FRP setup asks for a license")
		}
	})
	t.Run("open with a Pro key", func(t *testing.T) {
		withPro(t)
		for _, c := range calls {
			if rr := c.run(); apiCode(t, rr) == "E-LIC-01" {
				t.Errorf("%s: still locked: %s", c.name, rr.Body.String())
			}
		}
		if backhaulLocked("backhaul") {
			t.Error("engine switch to Backhaul locked with a Pro key")
		}
	})
}

// An update replaces only the binary. A key activated once must be active in
// the new process with no action from the admin: from license.key, and from
// panel.json alone when license.key is gone.
func TestLicenseSurvivesUpdate(t *testing.T) {
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
		activeLicense, licenseCheckedAt = nil, time.Now()
		activeLicenseMu.Unlock()
	})
	cfg = panelConfig{Username: "admin", PassHash: hashPassword("Secret-123"), Port: 7777, BasePath: "p"}
	saveCfg()
	cfgLoaded.Store(true)

	// the customer's key from before this release: Bagher only
	token := generateTestToken(t, "C1", getMachineHash(), []string{"bagher"}, time.Now().Add(24*time.Hour).Unix(), priv)
	rr := httptest.NewRecorder()
	handleLicensePost(rr, httptest.NewRequest("POST", "/api/license", strings.NewReader(`{"key":"`+token+`"}`)))
	if rr.Code != 200 {
		t.Fatalf("activate: %d %s", rr.Code, rr.Body.String())
	}

	restart := func() { // what a new binary does at start (main: loadOrInit, then the license)
		cfg = panelConfig{}
		cfgLoaded.Store(false)
		activeLicenseMu.Lock()
		activeLicense, licenseCheckedAt = nil, time.Time{}
		activeLicenseMu.Unlock()
		loadOrInit()
		loadLicenseFromDisk()
	}
	check := func(when string) {
		t.Helper()
		for _, f := range proFeatures {
			if !hasPro(f) {
				t.Errorf("%s: %s locked", when, f)
			}
		}
		rr := httptest.NewRecorder()
		handleLicenseGet(rr, httptest.NewRequest("GET", "/api/license", nil))
		var v struct {
			Valid bool     `json:"is_valid"`
			Pro   []string `json:"pro_features"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &v)
		if !v.Valid || len(v.Pro) != len(proFeatures) {
			t.Errorf("%s: /api/license %s", when, rr.Body.String())
		}
	}

	restart()
	check("after update")
	_ = os.Remove(filepath.Join(configDir, "license.key"))
	_ = os.Remove("/etc/hashem/license.key")
	restart()
	check("after update, license.key gone, key only in panel.json")
	if _, err := os.Stat(filepath.Join(configDir, "license.key")); err != nil {
		t.Error("license.key not written back from panel.json")
	}
	restart()
	check("second update")
}
