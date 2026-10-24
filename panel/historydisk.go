package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Durable link history: a small JSON snapshot so the graph survives a panel
// restart or update. Written at most every histSaveEvery and on clean exit;
// loaded at start. Only points newer than 24 h are kept. Failure to read or
// write never affects the panel (history is a convenience, not state).

const histSaveEvery = 5 * time.Minute

func histFile() string { return filepath.Join(configDir, "history.json") }

type histDisk struct {
	Version int                    `json:"v"`
	SavedAt int64                  `json:"saved_at"`
	Links   map[string][]histPoint `json:"links"`
}

func (h *histStore) save(path string, now time.Time) error {
	h.mu.Lock()
	d := histDisk{Version: 1, SavedAt: now.Unix(), Links: map[string][]histPoint{}}
	cut := now.Add(-24 * time.Hour).Unix()
	for name, r := range h.links {
		var pts []histPoint
		for _, p := range r.ordered() {
			if p.T >= cut {
				pts = append(pts, p)
			}
		}
		if len(pts) > 0 {
			d.Links[name] = pts
		}
	}
	h.mu.Unlock()
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path) // atomic: a crash never leaves a half-written file
}

// load restores points younger than 24 h. Corrupt or unknown-version files
// are ignored. It never overwrites data already collected in memory.
func (h *histStore) load(path string, now time.Time) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var d histDisk
	if json.Unmarshal(b, &d) != nil || d.Version != 1 {
		return 0
	}
	cut := now.Add(-24 * time.Hour).Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for name, pts := range d.Links {
		if len(h.links) >= maxLinks {
			break
		}
		if _, exists := h.links[name]; exists {
			continue
		}
		r := &histRing{}
		var prev int64
		for _, p := range pts {
			if p.T < cut || p.T > now.Unix()+60 || p.T <= prev { // old, future, or out of order
				continue
			}
			prev = p.T
			r.add(p)
			r.lastT = p.T
			n++
		}
		if len(r.pts) > 0 {
			h.links[name] = r // counters (rx/tx) restart: haveC stays false
		}
	}
	return n
}

// startHistoryPersistence loads once and then saves periodically until ctx ends.
func startHistoryPersistence(stop <-chan struct{}) {
	linkHist.load(histFile(), time.Now())
	go func() {
		t := time.NewTicker(histSaveEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = linkHist.save(histFile(), time.Now())
			case <-stop:
				_ = linkHist.save(histFile(), time.Now())
				return
			}
		}
	}()
}
