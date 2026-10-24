package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMigrateLegacyBackhaul(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no systemd units on windows")
	}
	dir := t.TempDir()
	oldDir, oldRun := legacyBackhaulUnitDir, legacyBackhaulMigrate
	defer func() { legacyBackhaulUnitDir, legacyBackhaulMigrate = oldDir, oldRun }()
	legacyBackhaulUnitDir = dir
	calls := 0
	legacyBackhaulMigrate = func() ([]byte, error) { calls++; return []byte("\x1b[0;32m[✔️] moved\x1b[0m\n"), nil }

	// Hashem's own units are not legacy: nothing to migrate.
	for _, u := range []string{"backhaul-server.service", "backhaul-server-2.service", "backhaul-client.service"} {
		if err := os.WriteFile(filepath.Join(dir, u), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	migrateLegacyBackhaul()
	if calls != 0 {
		t.Fatalf("migrate ran for Hashem units (%d calls)", calls)
	}

	if err := os.WriteFile(filepath.Join(dir, "backhaul-iran2020.service"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backhaul-kharej3030.service"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if got := legacyBackhaulUnits(); len(got) != 2 {
		t.Fatalf("legacyBackhaulUnits = %v", got)
	}
	migrateLegacyBackhaul()
	if calls != 1 {
		t.Fatalf("migrate calls = %d, want 1", calls)
	}
}
