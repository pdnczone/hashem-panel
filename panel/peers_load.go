package main

// Reading peers.json so that one damaged record, or a damaged file, never
// hides every tunnel.
//
// peers.json is written by hashem.sh (Python one-liners) and by the panel. A
// value of the wrong type in one record ("id": "3", "ports": "443, 2083",
// "no_gre": "1") used to fail the whole decode: every foreign server vanished
// from the panel and could not be removed there, while its services kept
// running. A write cut short (a killed installer, a full disk) left a file
// nothing could read. Now:
//
//   - each record is decoded on its own, with numbers, lists and switches
//     read in either form; only a record that is still unreadable is left out,
//     and the log says which one;
//   - the last copy that was read in full is kept as peers.json.bak, and is
//     used while peers.json cannot be read at all;
//   - the panel writes peers.json through a temporary file, so a reader never
//     sees half a file.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

func peersBackupFile() string { return peersFile() + ".bak" }

// decodePeers reads a peers.json document. It fails only when the document
// itself cannot be read; a record that cannot be read is skipped and named in
// skipped.
func decodePeers(data []byte) (recs []peerRecord, skipped []string, err error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("the file is empty")
	}
	var doc struct {
		Peers []json.RawMessage `json:"peers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	for i, raw := range doc.Peers {
		var p peerRecord
		if err := json.Unmarshal(raw, &p); err == nil {
			recs = append(recs, p)
			continue
		}
		p, perr := decodePeerLenient(raw)
		if perr != nil {
			skipped = append(skipped, fmt.Sprintf("record %d: %v", i+1, perr))
			continue
		}
		recs = append(recs, p)
	}
	return recs, skipped, nil
}

// decodePeerLenient reads one record whose values have the wrong JSON type:
// numbers written as strings, a port list written as one string, switches
// written as "1"/"true", a name written as a number.
func decodePeerLenient(raw json.RawMessage) (peerRecord, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return peerRecord{}, err
	}
	for _, k := range []string{"id", "frp_port"} {
		if v, ok := m[k]; ok {
			n, ok := anyInt(v)
			if !ok {
				return peerRecord{}, fmt.Errorf("%s is not a number (%v)", k, v)
			}
			m[k] = n
		}
	}
	if v, ok := m["ports"]; ok {
		m["ports"] = anyInts(v)
	}
	if v, ok := m["raw_ports"]; ok {
		if a, isList := v.([]any); isList {
			out := []string{}
			for _, x := range a {
				out = append(out, strings.TrimSpace(fmt.Sprint(x)))
			}
			m["raw_ports"] = out
		}
	}
	for _, k := range []string{"no_gre", "legacy", "use_encryption", "use_compression"} {
		if v, ok := m[k]; ok {
			m[k] = anyBool(v)
		}
	}
	for _, k := range []string{"name", "local_pub", "remote_pub", "local_gre", "peer_gre", "token", "gre_if",
		"frps_svc", "carrier", "engine", "transport", "proxy_protocol", "frp_transport"} {
		if v, ok := m[k]; ok {
			switch v.(type) {
			case string:
			case nil:
				delete(m, k)
			default:
				m[k] = fmt.Sprint(v)
			}
		}
	}
	fixed, err := json.Marshal(m)
	if err != nil {
		return peerRecord{}, err
	}
	var p peerRecord
	if err := json.Unmarshal(fixed, &p); err != nil {
		return peerRecord{}, err
	}
	if p.ID <= 0 {
		return peerRecord{}, fmt.Errorf("it has no id")
	}
	return p, nil
}

func anyInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), x == float64(int(x))
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	case bool:
		return 0, false
	case nil:
		return 0, true
	}
	return 0, false
}

// anyInts reads a port list: [443, "2083"], "443, 2083" or "443 2083". Ranges
// and mappings ("10000-10050", "8080=80") keep their first port, as the
// numeric list hashem.sh writes does.
func anyInts(v any) []int {
	var parts []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			parts = append(parts, strings.TrimSpace(fmt.Sprint(e)))
		}
	case string:
		parts = strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ' ' })
	case float64:
		parts = []string{strconv.Itoa(int(x))}
	}
	out := []int{}
	for _, s := range parts {
		s, _, _ = strings.Cut(s, "=")
		s, _, _ = strings.Cut(s, "-")
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 1 && n <= 65535 {
			out = append(out, n)
		}
	}
	return out
}

func anyBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

var peersBackup struct {
	sync.Mutex
	last []byte // the content last kept as peers.json.bak
}

// keepPeersBackup saves data, a peers.json read in full, as peers.json.bak
// when it differs from the copy kept last.
func keepPeersBackup(data []byte) {
	peersBackup.Lock()
	defer peersBackup.Unlock()
	if bytes.Equal(peersBackup.last, data) {
		return
	}
	if old, err := os.ReadFile(peersBackupFile()); err == nil && bytes.Equal(old, data) {
		peersBackup.last = data
		return
	}
	if atomicWriteFile(peersBackupFile(), data, 0600) == nil {
		peersBackup.last = data
	}
}

// loadPeersFile is loadPeers' work: peers.json, else its last good copy.
func loadPeersFile() []peerRecord {
	data, err := os.ReadFile(peersFile())
	if err != nil {
		return nil
	}
	recs, skipped, derr := decodePeers(data)
	if derr == nil {
		if len(skipped) > 0 {
			logPeersSkipped(skipped)
		} else {
			keepPeersBackup(data)
		}
		return recs
	}
	logPeersDecodeErr(derr)
	if bak, err := os.ReadFile(peersBackupFile()); err == nil {
		if recs, _, err := decodePeers(bak); err == nil {
			return recs
		}
	}
	return nil
}

var peersSkippedLog struct {
	sync.Mutex
	last string
}

// logPeersSkipped says once per change which records were left out.
func logPeersSkipped(skipped []string) {
	msg := strings.Join(skipped, "; ")
	peersSkippedLog.Lock()
	defer peersSkippedLog.Unlock()
	if msg == peersSkippedLog.last {
		return
	}
	peersSkippedLog.last = msg
	log.Printf("peers.json: left out what cannot be read (the other tunnels are shown): %s", msg)
}

// savePeersFile replaces peers.json in one step and keeps the new content
// as its last good copy.
func savePeersFile(data []byte) error {
	if err := atomicWriteFile(peersFile(), data, 0600); err != nil {
		return err
	}
	keepPeersBackup(data)
	return nil
}

// writePeers writes recs as peers.json. A record of the current file that
// cannot be read is kept as it is: recs came from loadPeers, which left it
// out, and rewriting the file must not delete a tunnel nobody removed.
func writePeers(recs []peerRecord) error {
	out := make([]any, 0, len(recs))
	for _, r := range recs {
		out = append(out, r)
	}
	if cur, err := os.ReadFile(peersFile()); err == nil {
		var doc struct {
			Peers []json.RawMessage `json:"peers"`
		}
		if json.Unmarshal(cur, &doc) == nil {
			for _, raw := range doc.Peers {
				var p peerRecord
				if json.Unmarshal(raw, &p) == nil {
					continue
				}
				if _, err := decodePeerLenient(raw); err != nil {
					out = append(out, raw)
				}
			}
		}
	}
	data, err := json.MarshalIndent(map[string]any{"peers": out}, "", "  ")
	if err != nil {
		return err
	}
	return savePeersFile(append(data, '\n'))
}

// atomicWriteFile writes data next to path and renames it over path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
