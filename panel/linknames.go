package main

// Names for the links that have no record of their own to hold one: the
// main tunnel ("main", the first foreign server, or the Iran server on a
// foreign server) and Bagher's foreign servers ("bagher-1", "bagher-N").
// Peers and Xray links keep their names in their own records.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var linkNamesMu sync.Mutex

func linkNamesPath() string { return filepath.Join(configDir, "link_names.json") }

var linkNameKeyRe = regexp.MustCompile(`^(main|bagher-[1-9][0-9]{0,3})$`)

func loadLinkNames() map[string]string {
	m := map[string]string{}
	if data, err := os.ReadFile(linkNamesPath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// linkLabel is a link's name, "" when it has none.
func linkLabel(key string) string {
	linkNamesMu.Lock()
	defer linkNamesMu.Unlock()
	return loadLinkNames()[key]
}

// validLinkName checks a name a user typed: up to 40 characters, nothing that
// could break the markup it is shown in.
func validLinkName(name string) error {
	if len([]rune(name)) > 40 || strings.ContainsAny(name, "<>\"'`\\\n\r\t") {
		return fmt.Errorf("name: up to 40 characters, no quotes, angle brackets or backslashes")
	}
	return nil
}

// setLinkName stores a link's name; "" removes it.
func setLinkName(key, name string) error {
	name = strings.TrimSpace(name)
	if !linkNameKeyRe.MatchString(key) {
		return fmt.Errorf("unknown link %q", key)
	}
	if err := validLinkName(name); err != nil {
		return err
	}
	linkNamesMu.Lock()
	defer linkNamesMu.Unlock()
	m := loadLinkNames()
	if name == "" {
		delete(m, key)
	} else {
		m[key] = name
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(linkNamesPath(), data, 0o600)
}

// dropLinkNames removes the names whose key starts with prefix ("bagher-").
func dropLinkNames(prefix string) {
	linkNamesMu.Lock()
	defer linkNamesMu.Unlock()
	m := loadLinkNames()
	changed := false
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			delete(m, k)
			changed = true
		}
	}
	if changed {
		if data, err := json.MarshalIndent(m, "", "  "); err == nil {
			_ = writeFileAtomic(linkNamesPath(), data, 0o600)
		}
	}
}

// handleLinkName renames a link: POST /api/link-name {"key":"main","name":"Frankfurt"}.
func handleLinkName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeAPIError(w, r, "E-ACTION-01", "invalid json")
		return
	}
	if err := setLinkName(req.Key, req.Name); err != nil {
		writeAPIError(w, r, "E-ACTION-01", err.Error())
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "key": req.Key, "name": strings.TrimSpace(req.Name)})
}
