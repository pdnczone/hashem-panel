package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func handlePeersGet(w http.ResponseWriter, r *http.Request) {
	if idStr := r.URL.Query().Get("id"); idStr != "" {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			writeAPIError(w, r, "E-PEER-05", "")
			return
		}
		script, err := greScriptPath()
		if err != nil {
			writeAPIError(w, r, "E-INSTALL-01", err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", script, "peer-token", "--id", strconv.Itoa(id))
		cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			writeAPIError(w, r, "E-PEER-04", strings.TrimSpace(string(out)))
			return
		}
		resp := map[string]string{"id": idStr}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		resp["token"] = strings.TrimSpace(lines[0])
		for _, ln := range lines[1:] {
			if b, ok := strings.CutPrefix(strings.TrimSpace(ln), "BUNDLE:"); ok {
				resp["bundle"] = strings.TrimSpace(b)
			}
		}
		if _, ok := resp["bundle"]; !ok {
			// old hashem.sh prints token only: rebuild the bundle from the
			// registry record (live Iran pub + port fill the rest).
			if p := findPeer(id); p != nil {
				resp["bundle"] = MakeBundle(p.LocalPub, p.FrpPort, p.LocalGre, p.PeerGre, resp["token"], p.Ports, p.FRPTransport)
			}
		}
		writeJSON(w, resp)
		return
	}
	snap := currentSnapshot()
	setSnapshotAgeHeader(w, snap)
	peers := snap.PeersAged()
	writeJSON(w, map[string]any{"peers": peers, "peer_count": len(peers), "max": maxPeers(), "snapshot_age_ms": snap.AgeMs()})
}

// maxPeers is the foreign-server cap; hashem.sh enforces the same value
// (MAX_PEERS, also overridable with GRE_MAX_PEERS).
func maxPeers() int {
	if v := os.Getenv("GRE_MAX_PEERS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			return parsed
		}
	}
	return 10
}

// POST /api/peers just proxies validation errors from /api/setup role=add-peer.
// The real creation path is /api/setup (role add-peer) so only one code path
// shells out to hashem.sh. This endpoint exists for future per-peer edits.
func handlePeersPost(w http.ResponseWriter, r *http.Request) {
	writeAPIError(w, r, "E-PEER-06", "")
}

// PATCH /api/peers — edit the configuration of an existing peer tunnel or main tunnel.
// Body: { "id": N, "name": "...", "remote_pub": "...", "carrier": "...", "ports": [443, 2083] }
// Strategy (graceful degradation):
//  1. Try hashem.sh edit-peer --id N ... (or edit-peer-ports).
//  2. Fallback to direct edit: update peers.json, adjust kernel GRE remote endpoint,
//     persist systemd unit, apply carrier mode, rewrite TOML proxy blocks, reload service, and allow UFW.
type peerPatchRequest struct {
	ID             int       `json:"id"`
	Name           string    `json:"name,omitempty"`
	RemotePub      string    `json:"remote_pub,omitempty"`
	Carrier        string    `json:"carrier,omitempty"`
	Engine         string    `json:"engine,omitempty"`
	Transport      string    `json:"transport,omitempty"`
	Ports          *[]int    `json:"ports,omitempty"`
	RawPorts       *[]string `json:"raw_ports,omitempty"`
	ProxyProtocol  string    `json:"proxy_protocol,omitempty"`
	FRPTransport   string    `json:"frp_transport,omitempty"`
	UseEncryption  *bool     `json:"use_encryption,omitempty"`
	UseCompression *bool     `json:"use_compression,omitempty"`
}

func (p *peerPatchRequest) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID             any             `json:"id"`
		Name           string          `json:"name,omitempty"`
		RemotePub      string          `json:"remote_pub,omitempty"`
		Carrier        string          `json:"carrier,omitempty"`
		Engine         string          `json:"engine,omitempty"`
		Transport      string          `json:"transport,omitempty"`
		Ports          json.RawMessage `json:"ports,omitempty"`
		RawPorts       json.RawMessage `json:"raw_ports,omitempty"`
		ProxyProtocol  string          `json:"proxy_protocol,omitempty"`
		FRPTransport   string          `json:"frp_transport,omitempty"`
		UseEncryption  *bool           `json:"use_encryption,omitempty"`
		UseCompression *bool           `json:"use_compression,omitempty"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.ProxyProtocol = raw.ProxyProtocol
	p.FRPTransport = raw.FRPTransport
	p.UseEncryption = raw.UseEncryption
	p.UseCompression = raw.UseCompression

	if raw.ID != nil {
		switch v := raw.ID.(type) {
		case float64:
			p.ID = int(v)
		case string:
			v = strings.TrimSpace(v)
			if v != "" {
				if idNum, err := strconv.Atoi(v); err == nil {
					p.ID = idNum
				} else {
					return fmt.Errorf("invalid id: %s", v)
				}
			}
		case int:
			p.ID = v
		default:
			return fmt.Errorf("invalid id type")
		}
	}

	p.Name = raw.Name
	p.RemotePub = raw.RemotePub
	p.Carrier = raw.Carrier
	p.Engine = raw.Engine
	p.Transport = raw.Transport

	parsePorts := func(msg json.RawMessage) ([]int, []string, bool) {
		trimmed := strings.TrimSpace(string(msg))
		if trimmed == "" || trimmed == "null" {
			return nil, nil, false
		}
		// String format: e.g. "443, 2083" or "8080=80"
		if strings.HasPrefix(trimmed, `"`) {
			var s string
			if err := json.Unmarshal(msg, &s); err == nil {
				s = strings.TrimSpace(s)
				if s == "" {
					return []int{}, []string{}, true
				}
				var nums []int
				var raws []string
				parts := strings.Split(s, ",")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					raws = append(raws, part)
					if n, err := strconv.Atoi(part); err == nil {
						nums = append(nums, n)
					}
				}
				return nums, raws, true
			}
		}
		// Array format: e.g. [443, 2083] or ["443", "8080=80"]
		var slice []any
		if err := json.Unmarshal(msg, &slice); err == nil {
			var nums []int
			var raws []string
			for _, item := range slice {
				switch v := item.(type) {
				case float64:
					n := int(v)
					nums = append(nums, n)
					raws = append(raws, strconv.Itoa(n))
				case string:
					v = strings.TrimSpace(v)
					if v != "" {
						raws = append(raws, v)
						if n, err := strconv.Atoi(v); err == nil {
							nums = append(nums, n)
						}
					}
				}
			}
			return nums, raws, true
		}
		return nil, nil, false
	}

	if len(raw.RawPorts) > 0 {
		nums, raws, ok := parsePorts(raw.RawPorts)
		if ok {
			p.RawPorts = &raws
			if len(nums) > 0 {
				p.Ports = &nums
			}
		}
	}

	if len(raw.Ports) > 0 {
		nums, raws, ok := parsePorts(raw.Ports)
		if ok {
			if p.Ports == nil || len(*p.Ports) == 0 {
				p.Ports = &nums
			}
			if p.RawPorts == nil || len(*p.RawPorts) == 0 {
				p.RawPorts = &raws
			}
		}
	}

	return nil
}

func handlePeersPatch(w http.ResponseWriter, r *http.Request) {
	var body peerPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, r, "E-PEER-07", "bad request body: "+err.Error())
		return
	}
	if body.ID < 0 {
		writeAPIError(w, r, "E-PEER-07", "id must be >= 0")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.RemotePub = strings.TrimSpace(body.RemotePub)
	body.Carrier = strings.TrimSpace(body.Carrier)
	body.Engine = strings.TrimSpace(body.Engine)
	body.Transport = strings.TrimSpace(body.Transport)

	// Explicit empty ports array: {"ports": []} or {"raw_ports": []} is rejected
	if body.Ports != nil && len(*body.Ports) == 0 {
		writeAPIError(w, r, "E-PEER-07", "ports list is empty")
		return
	}
	if body.RawPorts != nil && len(*body.RawPorts) == 0 {
		writeAPIError(w, r, "E-PEER-07", "raw_ports list is empty")
		return
	}

	// Must provide at least one field to update
	if body.Name == "" && body.RemotePub == "" && body.Carrier == "" && body.Engine == "" && body.Transport == "" && body.Ports == nil && body.RawPorts == nil {
		writeAPIError(w, r, "E-PEER-07", "no fields to update")
		return
	}

	// Validate raw ports if provided
	if body.RawPorts != nil {
		for _, rp := range *body.RawPorts {
			if !isValidPortOrRangeOrMapping(rp) {
				writeAPIError(w, r, "E-PEER-07", fmt.Sprintf("invalid port/range/mapping: %s", rp))
				return
			}
		}
		if body.Ports == nil {
			extracted := extractNumericPorts(*body.RawPorts)
			body.Ports = &extracted
		}
	}

	// Validate remote public IP if provided
	if body.RemotePub != "" {
		// a tunnel over GRE needs IPv4 at both ends; Backhaul without GRE
		// takes either family
		v6ok := false
		for _, p := range loadPeers() {
			if p.ID == body.ID {
				v6ok = p.NoGre || p.GreIf == "none"
			}
		}
		if f := ipFamily(body.RemotePub); f == 0 || f == 6 && !v6ok {
			msg := "invalid remote public IP"
			if f == 6 {
				msg = "a tunnel over GRE needs the foreign server's IPv4 address"
			}
			writeAPIError(w, r, "E-PEER-07", msg)
			return
		}
		if clash := peerDuplicateIPClash(body.RemotePub, body.ID); clash != "" {
			writeAPIError(w, r, "E-PEER-03", "IP "+body.RemotePub+" already used by peer "+clash)
			return
		}
	}

	// Validate carrier if provided
	if body.Carrier != "" {
		c := strings.ToLower(body.Carrier)
		if c != "direct" && !strings.HasPrefix(c, "fou:") && !strings.HasPrefix(c, "wss:") && c != "fou" && c != "wss" {
			writeAPIError(w, r, "E-PEER-07", "invalid carrier mode (must be direct, fou:PORT, or wss:PORT)")
			return
		}
	}

	// Validate ports if provided
	if body.Ports != nil {
		for _, p := range *body.Ports {
			if p < 1 || p > 65535 {
				writeAPIError(w, r, "E-PEER-07", fmt.Sprintf("invalid port %d", p))
				return
			}
		}
	}

	// Case 1: ID == 0 -> Edit Main / Base Tunnel
	if body.ID == 0 {
		// The main tunnel's name lives in link_names.json (it has no record of
		// its own); a rename alone does not touch the running tunnel.
		if err := validLinkName(body.Name); err != nil {
			writeAPIError(w, r, "E-PEER-07", err.Error())
			return
		}
		if body.Name != "" {
			if err := setLinkName("main", body.Name); err != nil {
				writeAPIError(w, r, "E-PEER-07", err.Error())
				return
			}
		}
		if body.RemotePub == "" && body.Carrier == "" && body.Engine == "" && body.Transport == "" && body.Ports == nil && body.RawPorts == nil {
			writeJSON(w, map[string]any{"status": "ok", "output": "main tunnel renamed"})
			return
		}
		excludeID := 0
		var legacyPeer *peerRecord
		for _, p := range loadPeers() {
			if p.Legacy || p.ID == 1 {
				excludeID = p.ID
				c := p
				legacyPeer = &c
				break
			}
		}
		if body.Ports != nil {
			if clash := peerPortClash(*body.Ports, excludeID); clash != "" {
				writeAPIError(w, r, "E-PEER-02", "port "+clash+" is already served by another tunnel")
				return
			}
		}
		warnMsg, err := editMainTunnelDirect(body, legacyPeer)
		if err != nil {
			writeAPIError(w, r, "E-PEER-07", err.Error())
			return
		}
		bundle := generateMainBundle(body, legacyPeer)
		resp := map[string]any{"status": "ok", "output": "main tunnel configuration updated"}
		if bundle != "" {
			resp["bundle"] = bundle
		}
		if warnMsg != "" {
			resp["warning"] = warnMsg
		}
		writeJSON(w, resp)
		return
	}

	// Case 2: ID > 0 -> Edit Peer Tunnel
	peer := findPeer(body.ID)
	if peer == nil {
		writeAPIError(w, r, "E-PEER-05", fmt.Sprintf("peer %d not found", body.ID))
		return
	}
	if body.Ports != nil {
		if clash := peerPortClash(*body.Ports, body.ID); clash != "" {
			writeAPIError(w, r, "E-PEER-02", "port "+clash+" is already served by another tunnel")
			return
		}
	}

	// 1. Try installer if it supports edit-peer or edit-peer-ports (for standard FRP peers without transport/raw-port changes)
	if peer.Engine != "backhaul" && body.Transport == "" && body.RawPorts == nil {
		if out, err := editPeerViaInstaller(body); err == nil {
			bundle := generatePeerBundle(peer, body)
			resp := map[string]any{"status": "ok", "output": out}
			if bundle != "" {
				resp["bundle"] = bundle
			}
			writeJSON(w, resp)
			return
		}
	}

	// 2. Direct edit: update peers.json, reconfigure GRE endpoint, systemd unit, carrier, toml, firewall
	warnMsg, err := editPeerDirect(peer, body)
	if err != nil {
		writeAPIError(w, r, "E-PEER-07", err.Error())
		return
	}
	bundle := generatePeerBundle(peer, body)
	resp := map[string]any{"status": "ok", "output": fmt.Sprintf("peer %d configuration updated", body.ID)}
	if bundle != "" {
		resp["bundle"] = bundle
	}
	if warnMsg != "" {
		resp["warning"] = warnMsg
	}
	writeJSON(w, resp)
}

// editPeerViaInstaller tries the installer subcommand for peer editing.
func editPeerViaInstaller(body peerPatchRequest) (string, error) {
	script, err := greScriptPath()
	if err != nil {
		return "", err
	}
	args := []string{script, "edit-peer", "--id", strconv.Itoa(body.ID)}
	if body.Name != "" {
		args = append(args, "--name", body.Name)
	}
	if body.RemotePub != "" {
		args = append(args, "--remote-pub", body.RemotePub)
	}
	if body.Carrier != "" {
		args = append(args, "--carrier", body.Carrier)
	}
	if body.ProxyProtocol != "" {
		args = append(args, "--proxy-protocol", body.ProxyProtocol)
	}
	if body.FRPTransport != "" {
		args = append(args, "--frp-transport", body.FRPTransport)
	}
	if body.UseEncryption != nil {
		if *body.UseEncryption {
			args = append(args, "--encrypt")
		} else {
			args = append(args, "--frp-encryption", "off")
		}
	}
	if body.UseCompression != nil {
		if *body.UseCompression {
			args = append(args, "--compress")
		} else {
			args = append(args, "--frp-compression", "off")
		}
	}
	if body.Ports != nil {
		strs := make([]string, len(*body.Ports))
		for i, p := range *body.Ports {
			strs[i] = strconv.Itoa(p)
		}
		args = append(args, "--ports", strings.Join(strs, ","))
	}
	ctxPatch, cancelPatch := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPatch()
	cmd := exec.CommandContext(ctxPatch, "bash", args...)
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
	out, runErr := cmd.CombinedOutput()
	o := strings.TrimSpace(stripANSI(string(out)))
	if runErr != nil {
		lower := strings.ToLower(o)
		if strings.Contains(lower, "unknown command") || strings.Contains(lower, "unknown flag") {
			// If edit-peer wasn't found but only ports are being updated, try legacy edit-peer-ports
			if body.Ports != nil && body.Name == "" && body.RemotePub == "" && body.Carrier == "" {
				strs := make([]string, len(*body.Ports))
				for i, p := range *body.Ports {
					strs[i] = strconv.Itoa(p)
				}
				cmdLegacy := exec.CommandContext(ctxPatch, "bash", script, "edit-peer-ports", "--id", strconv.Itoa(body.ID), "--ports", strings.Join(strs, ","))
				cmdLegacy.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+configDir)
				outLegacy, errLegacy := cmdLegacy.CombinedOutput()
				if errLegacy == nil {
					return strings.TrimSpace(stripANSI(string(outLegacy))), nil
				}
			}
			return "", fmt.Errorf("installer lacks edit-peer")
		}
		return o, runErr
	}
	invalidatePeerIfsCache()
	return o, nil
}

// editPeerDirect updates peers.json, GRE remote endpoint, systemd unit, carrier, and TOML proxy blocks.
func editPeerDirect(peer *peerRecord, req peerPatchRequest) (string, error) {
	var warning string

	// 1. Rewrite peers.json
	peers := loadPeers()
	for i := range peers {
		if peers[i].ID == peer.ID {
			if req.Name != "" {
				peers[i].Name = req.Name
			}
			if req.RemotePub != "" {
				peers[i].RemotePub = req.RemotePub
			}
			if req.Carrier != "" {
				peers[i].Carrier = req.Carrier
			}
			if req.Engine != "" {
				peers[i].Engine = req.Engine
			}
			if req.Transport != "" {
				peers[i].Transport = req.Transport
			}
			if req.ProxyProtocol != "" {
				peers[i].ProxyProtocol = req.ProxyProtocol
			}
			if req.FRPTransport != "" {
				peers[i].FRPTransport = req.FRPTransport
			}
			if req.UseEncryption != nil {
				peers[i].UseEncryption = *req.UseEncryption
			}
			if req.UseCompression != nil {
				peers[i].UseCompression = *req.UseCompression
			}
			if req.RawPorts != nil {
				peers[i].RawPorts = *req.RawPorts
				peers[i].Ports = extractNumericPorts(*req.RawPorts)
			} else if req.Ports != nil {
				peers[i].Ports = *req.Ports
				var rps []string
				for _, p := range *req.Ports {
					rps = append(rps, strconv.Itoa(p))
				}
				peers[i].RawPorts = rps
			}
		}
	}
	data, err := json.MarshalIndent(map[string]any{"peers": peers}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal peers: %w", err)
	}
	if err := os.WriteFile(peersFile(), append(data, '\n'), 0600); err != nil {
		return "", fmt.Errorf("write peers.json: %w", err)
	}

	greIf := peer.GreIf
	if greIf == "" {
		if peer.ID > 1 {
			greIf = fmt.Sprintf("gre-t%d", peer.ID)
		} else {
			greIf = "gre-tunnel"
		}
	}

	// 2. Reconfigure GRE remote endpoint if remote_pub changed (only if not standalone Backhaul)
	if !peer.NoGre && peer.Engine != "backhaul" && req.RemotePub != "" && req.RemotePub != peer.RemotePub {
		exec.Command("ip", "tunnel", "change", greIf, "remote", req.RemotePub).CombinedOutput()
		svcFile := fmt.Sprintf("/etc/systemd/system/%s.service", greIf)
		updateServiceRemoteIP(svcFile, peer.RemotePub, req.RemotePub)
		_ = runSystemctl("daemon-reload")
		_ = runSystemctl("restart", greIf+".service")

		if !testPing(req.RemotePub, 2) {
			warning = fmt.Sprintf("New remote IP %s did not reply to ping (peer may be offline or firewalling ICMP)", req.RemotePub)
		}
	}

	// 3. Apply carrier if changed
	if req.Carrier != "" && req.Carrier != peer.Carrier {
		_ = applyPeerCarrierDirect(greIf, req.Carrier)
	}

	// 4. Update ports if changed
	if req.RawPorts != nil || req.Ports != nil {
		var rawList []string
		if req.RawPorts != nil {
			rawList = *req.RawPorts
		} else if req.Ports != nil {
			for _, p := range *req.Ports {
				rawList = append(rawList, strconv.Itoa(p))
			}
		}
		var numList []int
		if req.Ports != nil {
			numList = *req.Ports
		} else {
			numList = extractNumericPorts(rawList)
		}

		if peer.Engine == "backhaul" || peer.Engine == "gre-backhaul" {
			tomlPath := filepath.Join(backhaulDir, fmt.Sprintf("server-%d.toml", peer.ID))
			if _, err := os.Stat(tomlPath); err != nil && peer.ID <= 1 {
				tomlPath = filepath.Join(backhaulDir, "config.toml")
			}
			if rawToml, err := os.ReadFile(tomlPath); err == nil {
				updated := rewriteBackhaulTomlPorts(string(rawToml), rawList)
				_ = writeTokenFile(tomlPath, []byte(updated))
			}
			svc := peer.FrpsSvc
			if svc == "" {
				if peer.ID > 1 {
					svc = fmt.Sprintf("backhaul-server-%d", peer.ID)
				} else {
					svc = "backhaul-server"
				}
			}
			_ = runSystemctl("reload-or-restart", svc)
			allowUFWPorts(numList)
		} else {
			// FRP proxies are defined by frpc on the foreign server; frps only
			// accepts them. Writing [[proxies]] into frps-N.toml is invalid
			// (strict config rejects it) and took the peer's tunnel down, so
			// the Iran side only records the ports and opens the firewall.
			allowUFWPorts(numList)
			if warning != "" {
				warning += "; "
			}
			warning += "Ports saved. Apply them on the foreign server too (re-run its setup with the updated bundle)."
		}
	}

	invalidatePeerIfsCache()
	return warning, nil
}

// editMainTunnelDirect updates configuration for the main tunnel (id 0).
func editMainTunnelDirect(req peerPatchRequest, legacyPeer *peerRecord) (string, error) {
	var warning string

	// 1. If legacy peer exists in peers.json, update it
	if legacyPeer != nil {
		peers := loadPeers()
		for i := range peers {
			if peers[i].Legacy || peers[i].ID == 1 {
				if req.Name != "" {
					peers[i].Name = req.Name
				}
				if req.RemotePub != "" {
					peers[i].RemotePub = req.RemotePub
				}
				if req.Carrier != "" {
					peers[i].Carrier = req.Carrier
				}
				if req.Engine != "" {
					peers[i].Engine = req.Engine
				}
				if req.Transport != "" {
					peers[i].Transport = req.Transport
				}
				if req.RawPorts != nil {
					peers[i].RawPorts = *req.RawPorts
					peers[i].Ports = extractNumericPorts(*req.RawPorts)
				} else if req.Ports != nil {
					peers[i].Ports = *req.Ports
					var rps []string
					for _, p := range *req.Ports {
						rps = append(rps, strconv.Itoa(p))
					}
					peers[i].RawPorts = rps
				}
			}
		}
		if data, err := json.MarshalIndent(map[string]any{"peers": peers}, "", "  "); err == nil {
			_ = os.WriteFile(peersFile(), append(data, '\n'), 0600)
		}
	}

	// 2. Remote IP change for gre-tunnel
	if req.RemotePub != "" {
		exec.Command("ip", "tunnel", "change", "gre-tunnel", "remote", req.RemotePub).CombinedOutput()
		oldIP := ""
		if legacyPeer != nil {
			oldIP = legacyPeer.RemotePub
		}
		updateServiceRemoteIP("/etc/systemd/system/gre-tunnel.service", oldIP, req.RemotePub)
		_ = runSystemctl("daemon-reload")
		_ = runSystemctl("restart", "gre-tunnel.service")

		if !testPing(req.RemotePub, 2) {
			warning = fmt.Sprintf("New remote IP %s did not reply to ping", req.RemotePub)
		}
	}

	// 3. Carrier mode change
	if req.Carrier != "" {
		_ = applyPeerCarrierDirect("gre-tunnel", req.Carrier)
		_, _ = runHashemCarrierCmd("set", req.Carrier)
	}

	// 4. Ports change
	if req.RawPorts != nil {
		if rawToml, err := os.ReadFile(filepath.Join(backhaulDir, "config.toml")); err == nil {
			updated := rewriteBackhaulTomlPorts(string(rawToml), *req.RawPorts)
			_ = writeTokenFile(filepath.Join(backhaulDir, "config.toml"), []byte(updated))
			_ = runSystemctl("reload-or-restart", "backhaul-server")
			allowUFWPorts(extractNumericPorts(*req.RawPorts))
		}
	}
	if req.Ports != nil {
		_ = editMainTunnelPortsDirect(*req.Ports)
	}

	return warning, nil
}

func generatePeerBundle(peer *peerRecord, req peerPatchRequest) string {
	if peer == nil {
		return ""
	}
	localPub := peer.LocalPub
	if localPub == "" {
		localPub = detectPublicIP()
	}
	ports := peer.Ports
	if req.Ports != nil {
		ports = *req.Ports
	}
	rawPorts := peer.RawPorts
	if req.RawPorts != nil {
		rawPorts = *req.RawPorts
	} else if len(rawPorts) == 0 && len(ports) > 0 {
		rawPorts = make([]string, len(ports))
		for i, p := range ports {
			rawPorts[i] = strconv.Itoa(p)
		}
	}
	token := peer.Token
	if token == "" {
		tomlPath := filepath.Join(frpDir, fmt.Sprintf("frps-%d.toml", peer.ID))
		if _, err := os.Stat(tomlPath); err != nil && peer.ID == 1 {
			tomlPath = filepath.Join(frpDir, "frps.toml")
		}
		if raw, err := os.ReadFile(tomlPath); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(line, "auth.token") || strings.Contains(line, "token =") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						token = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				}
			}
		}
		if token == "" {
			bhPath := filepath.Join(backhaulDir, fmt.Sprintf("server-%d.toml", peer.ID))
			if _, err := os.Stat(bhPath); err != nil && peer.ID == 1 {
				bhPath = filepath.Join(backhaulDir, "config.toml")
			}
			if raw, err := os.ReadFile(bhPath); err == nil {
				for _, line := range strings.Split(string(raw), "\n") {
					if strings.Contains(line, "token =") {
						parts := strings.Split(line, "=")
						if len(parts) == 2 {
							token = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						}
					}
				}
			}
		}
	}
	transport := peer.Transport
	if req.Transport != "" {
		transport = req.Transport
	}
	engine := peer.Engine
	if req.Engine != "" {
		engine = req.Engine
	}

	if localPub == "" || token == "" || peer.FrpPort <= 0 {
		return ""
	}
	if engine == "backhaul" {
		return MakeBackhaulBundle(localPub, peer.FrpPort, backhaulBundleTransport(transport, backhaulUDPPort(peer.FrpsSvc)), token, rawPorts)
	}
	if engine == "gre-backhaul" {
		if peer.LocalGre == "" || peer.PeerGre == "" {
			return ""
		}
		return MakeGreBackhaulBundle(localPub, peer.FrpPort, peer.LocalGre, peer.PeerGre, backhaulBundleTransport(transport, backhaulUDPPort(peer.FrpsSvc)), token, rawPorts)
	}
	if peer.LocalGre == "" || peer.PeerGre == "" {
		return ""
	}
	return MakeBundle(localPub, peer.FrpPort, peer.LocalGre, peer.PeerGre, token, ports, peer.FRPTransport)
}

func generateMainBundle(req peerPatchRequest, legacyPeer *peerRecord) string {
	iranPub := detectPublicIP()
	frpPort := 7000
	iranGre := defaultIranGRE
	foreignGre := defaultForeignGRE
	token := ""
	engine := ""
	transport := "tcpmux"
	var ports []int
	var rawPorts []string
	if req.Ports != nil {
		ports = *req.Ports
	}
	if req.RawPorts != nil {
		rawPorts = *req.RawPorts
	}
	if legacyPeer != nil {
		if legacyPeer.LocalPub != "" {
			iranPub = legacyPeer.LocalPub
		}
		if legacyPeer.FrpPort > 0 {
			frpPort = legacyPeer.FrpPort
		}
		if legacyPeer.LocalGre != "" {
			iranGre = legacyPeer.LocalGre
		}
		if legacyPeer.PeerGre != "" {
			foreignGre = legacyPeer.PeerGre
		}
		token = legacyPeer.Token
		engine = legacyPeer.Engine
		if legacyPeer.Transport != "" {
			transport = legacyPeer.Transport
		}
		if len(ports) == 0 {
			ports = legacyPeer.Ports
		}
		if len(rawPorts) == 0 {
			rawPorts = legacyPeer.RawPorts
		}
	}
	if len(rawPorts) == 0 && len(ports) > 0 {
		rawPorts = make([]string, len(ports))
		for i, p := range ports {
			rawPorts[i] = strconv.Itoa(p)
		}
	}
	if token == "" {
		if raw, err := os.ReadFile(filepath.Join(frpDir, "frps.toml")); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(line, "auth.token") || strings.Contains(line, "token =") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						token = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					}
				}
			}
		}
		if token == "" {
			if raw, err := os.ReadFile(filepath.Join(backhaulDir, "config.toml")); err == nil {
				for _, line := range strings.Split(string(raw), "\n") {
					if strings.Contains(line, "token =") {
						parts := strings.Split(line, "=")
						if len(parts) == 2 {
							token = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						}
					}
				}
			}
		}
	}
	if iranPub == "" || token == "" {
		return ""
	}
	if engine == "backhaul" {
		return MakeBackhaulBundle(iranPub, frpPort, backhaulBundleTransport(transport, backhaulUDPPort("backhaul-server")), token, rawPorts)
	}
	if engine == "gre-backhaul" {
		return MakeGreBackhaulBundle(iranPub, frpPort, iranGre, foreignGre, backhaulBundleTransport(transport, backhaulUDPPort("backhaul-server")), token, rawPorts)
	}
	frpTrans := ""
	if req.FRPTransport != "" {
		frpTrans = req.FRPTransport
	} else if legacyPeer != nil {
		frpTrans = legacyPeer.FRPTransport
	}
	return MakeBundle(iranPub, frpPort, iranGre, foreignGre, token, ports, frpTrans)
}

// applyPeerCarrierDirect switches one tunnel interface: hashem.sh's
// carrier_apply does the device, encap, firewall and MTU (it used to switch
// every GRE interface, then this patched the encap by hand with the wrong
// WSS port).
func applyPeerCarrierDirect(greIf string, carrier string) error {
	_, err := runHashemCarrierCmd("set", carrier, "--if", greIf)
	return err
}

func updateServiceRemoteIP(serviceFile string, oldIP string, newIP string) {
	data, err := os.ReadFile(serviceFile)
	if err != nil {
		return
	}
	content := string(data)
	// Match oldIP only as a whole address: a plain substring replace also
	// rewrote 1.2.3.45 when oldIP was 1.2.3.4.
	exact := regexp.MustCompile(`(^|[^0-9.])` + regexp.QuoteMeta(oldIP) + `($|[^0-9.])`)
	if oldIP != "" && exact.MatchString(content) {
		// Repeat: back-to-back occurrences share a separator character, so
		// one pass can miss every second one.
		for i := 0; i < 4 && oldIP != newIP && exact.MatchString(content); i++ {
			content = exact.ReplaceAllString(content, "${1}"+newIP+"${2}")
		}
	} else {
		re := regexp.MustCompile(`remote\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
		content = re.ReplaceAllString(content, "remote "+newIP)
	}
	_ = os.WriteFile(serviceFile, []byte(content), 0644)
}

func testPing(ip string, timeoutSec int) bool {
	if ip == "" || net.ParseIP(ip) == nil {
		return false
	}
	cmd := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), ip)
	return cmd.Run() == nil
}

// editMainTunnelPortsDirect updates configuration for the main tunnel (id 0)
// across peers.json (if legacy peer 1 exists), /etc/frp/frpc.toml, /etc/frp/frps.toml,
// and system firewall.
func editMainTunnelPortsDirect(newPorts []int) error {
	editedAny := false

	// 1. If legacy peer exists in peers.json, update it
	peers := loadPeers()
	for i := range peers {
		if peers[i].Legacy || peers[i].ID == 1 {
			peers[i].Ports = newPorts
			editedAny = true
		}
	}
	if editedAny {
		data, err := json.MarshalIndent(map[string]any{"peers": peers}, "", "  ")
		if err == nil {
			_ = os.WriteFile(peersFile(), append(data, '\n'), 0600)
		}
	}

	// 2. Foreign client toml (/etc/frp/frpc.toml): the only place FRP
	// proxies live. frps.toml is left alone (see editPeerDirect).
	if rawToml, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml")); err == nil {
		updated := rewriteTomlPorts(string(rawToml), newPorts)
		_ = writeTokenFile(filepath.Join(frpDir, "frpc.toml"), []byte(updated))
		_ = runSystemctl("reload-or-restart", "frpc")
		editedAny = true
	}

	// 4. Open ports in UFW if active
	allowUFWPorts(newPorts)

	if !editedAny {
		// Still create a minimal peers record or return ok if it was applied
		return nil
	}
	return nil
}
