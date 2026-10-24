package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// setupBundle is a parsed
// hsh1_<IRAN_PUB>_<FRP_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TOKEN>[_<PORTS>][_fou<P1>-<P2>]
type setupBundle struct {
	Engine     string // "frp" | "backhaul" | "gre-backhaul"
	Transport  string // for backhaul: "tcpmux", "tcp", "ws", "wss", "wsmux", "wssmux"
	UDP        bool   // backhaul: forward UDP too (transport written as "tcpmux+udp3081")
	UDPPort    int    // backhaul: the UDP companion's control port
	IranPub    string
	FrpPort    int
	IranGre    string
	ForeignGre string
	Token      string
	Ports      []int
	RawPorts   []string
	FouPorts   []int
}

// MakeBundle builds the single foreign-setup string. Ports may be empty
// (base setup-iran omits them); when present they join with '-'.
func MakeBundle(iranPub string, frpPort int, iranGre, foreignGre, token string, ports []int, transport ...string) string {
	cfg := loadCarrierConfig()
	p1, p2 := cfg.FOUPort1, cfg.FOUPort2
	if p1 <= 0 {
		p1 = 443
	}
	if p2 <= 0 {
		p2 = 55555
	}
	s := bundlePrefix + iranPub + "_" + strconv.Itoa(frpPort) + "_" + iranGre + "_" + foreignGre + "_" + token
	portsPart := ""
	if len(ports) > 0 {
		strs := make([]string, len(ports))
		for i, p := range ports {
			strs[i] = strconv.Itoa(p)
		}
		portsPart = strings.Join(strs, "-")
	}
	fouPart := fmt.Sprintf("fou%d-%d", p1, p2)
	transPart := ""
	if len(transport) > 0 && transport[0] != "" && transport[0] != "tcp" {
		transPart = "_tr-" + transport[0]
	}
	if portsPart != "" {
		s += "_" + portsPart + "_" + fouPart + transPart
	} else {
		s += "__" + fouPart + transPart
	}
	return s
}

// bundleUDPMark follows a Backhaul bundle's transport when the tunnel forwards
// UDP too, with the UDP companion's own control port ("tcpmux+udp3081"): the
// foreign side then runs its companion against that port.
const bundleUDPMark = "+udp"

// backhaulBundleTransport is the transport field of a Backhaul bundle; udpPort
// is the companion's control port (0: no companion, no mark).
func backhaulBundleTransport(transport string, udpPort int) string {
	if transport == "" {
		transport = "tcpmux"
	}
	if udpPort > 0 && transport != "udp" && !strings.Contains(transport, bundleUDPMark) {
		return transport + bundleUDPMark + strconv.Itoa(udpPort)
	}
	return transport
}

// splitBundleTransport splits "tcpmux+udp3081" into the transport, whether UDP
// is forwarded too, and the companion's control port.
func splitBundleTransport(t string) (transport string, udp bool, udpPort int) {
	base, rest, found := strings.Cut(t, bundleUDPMark)
	if !found {
		return t, false, 0
	}
	if p, err := strconv.Atoi(rest); err == nil && p > 0 && p <= 65535 {
		udpPort = p
	}
	return base, true, udpPort
}

// MakeBackhaulBundle builds the Standalone Backhaul setup bundle (No-GRE).
// Format: bh1_<IRAN_PUB>_<BH_PORT>_<TRANSPORT>_<TOKEN>[_<PORTS>]
func MakeBackhaulBundle(iranPub string, bhPort int, transport, token string, ports []string) string {
	if transport == "" {
		transport = "tcpmux"
	}
	s := bundlePrefixBackhaul + iranPub + "_" + strconv.Itoa(bhPort) + "_" + transport + "_" + token
	if len(ports) > 0 {
		s += "_" + strings.Join(ports, ",")
	}
	return s
}

// MakeGreBackhaulBundle builds the GRE + Backhaul setup bundle.
// Format: gh1_<IRAN_PUB>_<BH_PORT>_<IRAN_GRE>_<FOREIGN_GRE>_<TRANSPORT>_<TOKEN>[_<PORTS>]
func MakeGreBackhaulBundle(iranPub string, bhPort int, iranGre, foreignGre, transport, token string, ports []string) string {
	if transport == "" {
		transport = "tcpmux"
	}
	s := bundlePrefixGreBackhaul + iranPub + "_" + strconv.Itoa(bhPort) + "_" + iranGre + "_" + foreignGre + "_" + transport + "_" + token
	if len(ports) > 0 {
		s += "_" + strings.Join(ports, ",")
	}
	return s
}

// ParseBackhaulBundle parses a Standalone Backhaul bundle (bh1_...).
func ParseBackhaulBundle(s string) (setupBundle, error) {
	var b setupBundle
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, bundlePrefixBackhaul) {
		return b, fmt.Errorf("not a backhaul bundle (must start with bh1_)")
	}
	rest := strings.TrimPrefix(s, bundlePrefixBackhaul)
	parts := strings.Split(rest, "_")
	if len(parts) < 4 || len(parts) > 5 {
		return b, fmt.Errorf("backhaul bundle must have 4 or 5 underscore parts (got %d)", len(parts))
	}
	iranPub, portS, transport, token := parts[0], parts[1], parts[2], parts[3]
	transport, udp, udpPort := splitBundleTransport(transport)
	if ipFamily(iranPub) == 0 { // no GRE: IPv4 or IPv6
		return b, fmt.Errorf("bad Iran public IP in bundle: %q", iranPub)
	}
	port, err := strconv.Atoi(portS)
	if err != nil || port < 1 || port > 65535 {
		return b, fmt.Errorf("bad control port in bundle: %q", portS)
	}
	if transport == "" {
		transport = "tcpmux"
	}
	if len(token) == 0 || len(token) > 128 {
		return b, fmt.Errorf("bad token in bundle (length 1-128)")
	}
	b = setupBundle{
		Engine:    "backhaul",
		UDP:       udp,
		UDPPort:   udpPort,
		Transport: transport,
		IranPub:   iranPub,
		FrpPort:   port,
		Token:     token,
	}
	if len(parts) == 5 && parts[4] != "" {
		rawPorts := parseRawPorts(parts[4])
		b.RawPorts = rawPorts
		b.Ports = extractNumericPorts(rawPorts)
	}
	return b, nil
}

// ParseGreBackhaulBundle parses a GRE+Backhaul bundle (gh1_...).
func ParseGreBackhaulBundle(s string) (setupBundle, error) {
	var b setupBundle
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, bundlePrefixGreBackhaul) {
		return b, fmt.Errorf("not a gre-backhaul bundle (must start with gh1_)")
	}
	rest := strings.TrimPrefix(s, bundlePrefixGreBackhaul)
	parts := strings.Split(rest, "_")
	if len(parts) < 6 || len(parts) > 7 {
		return b, fmt.Errorf("gre-backhaul bundle must have 6 or 7 underscore parts (got %d)", len(parts))
	}
	iranPub, portS, iranGre, foreignGre, transport, token := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
	transport, udp, udpPort := splitBundleTransport(transport)
	if net.ParseIP(iranPub) == nil || !isV4(iranPub) {
		return b, fmt.Errorf("bad Iran public IP in bundle: %q", iranPub)
	}
	port, err := strconv.Atoi(portS)
	if err != nil || port < 1 || port > 65535 {
		return b, fmt.Errorf("bad control port in bundle: %q", portS)
	}
	if net.ParseIP(iranGre) == nil || !isV4(iranGre) {
		return b, fmt.Errorf("bad Iran GRE IP in bundle: %q", iranGre)
	}
	if net.ParseIP(foreignGre) == nil || !isV4(foreignGre) {
		return b, fmt.Errorf("bad foreign GRE IP in bundle: %q", foreignGre)
	}
	if transport == "" {
		transport = "tcpmux"
	}
	if len(token) == 0 || len(token) > 128 {
		return b, fmt.Errorf("bad token in bundle (length 1-128)")
	}
	b = setupBundle{
		Engine:     "gre-backhaul",
		UDP:        udp,
		UDPPort:    udpPort,
		Transport:  transport,
		IranPub:    iranPub,
		FrpPort:    port,
		IranGre:    iranGre,
		ForeignGre: foreignGre,
		Token:      token,
	}
	if len(parts) == 7 && parts[6] != "" {
		rawPorts := parseRawPorts(parts[6])
		b.RawPorts = rawPorts
		b.Ports = extractNumericPorts(rawPorts)
	}
	return b, nil
}

// ParseBundle validates and parses any bundle (hsh1_..., bh1_..., or gh1_...).
func ParseBundle(s string) (setupBundle, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, bundlePrefixBackhaul) {
		return ParseBackhaulBundle(s)
	}
	if strings.HasPrefix(s, bundlePrefixGreBackhaul) {
		return ParseGreBackhaulBundle(s)
	}
	var b setupBundle
	if !strings.HasPrefix(s, bundlePrefix) {
		return b, fmt.Errorf("not a bundle (must start with hsh1_, bh1_, or gh1_)")
	}
	rest := strings.TrimPrefix(s, bundlePrefix)
	parts := strings.Split(rest, "_")
	if len(parts) < 5 || len(parts) > 8 {
		return b, fmt.Errorf("bundle must have between 5 and 8 underscore parts (got %d)", len(parts))
	}
	iranPub, portS, iranGre, foreignGre, token := parts[0], parts[1], parts[2], parts[3], parts[4]
	if net.ParseIP(iranPub) == nil || !isV4(iranPub) {
		return b, fmt.Errorf("bad Iran public IP in bundle: %q", iranPub)
	}
	port, err := strconv.Atoi(portS)
	if err != nil || port < 1 || port > 65535 {
		return b, fmt.Errorf("bad control port in bundle: %q", portS)
	}
	if net.ParseIP(iranGre) == nil || !isV4(iranGre) {
		return b, fmt.Errorf("bad Iran GRE IP in bundle: %q", iranGre)
	}
	if net.ParseIP(foreignGre) == nil || !isV4(foreignGre) {
		return b, fmt.Errorf("bad foreign GRE IP in bundle: %q", foreignGre)
	}
	if len(token) == 0 || len(token) > 128 {
		return b, fmt.Errorf("bad token in bundle (length 1-128)")
	}
	b = setupBundle{Engine: "frp", Transport: "tcp", IranPub: iranPub, FrpPort: port, IranGre: iranGre, ForeignGre: foreignGre, Token: token}
	for i := 5; i < len(parts); i++ {
		p := parts[i]
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "tr-") {
			b.Transport = strings.TrimPrefix(p, "tr-")
		} else if strings.HasPrefix(p, "fou") {
			fouRaw := strings.TrimPrefix(p, "fou")
			for _, portStr := range strings.Split(fouRaw, "-") {
				if fp, err := strconv.Atoi(portStr); err == nil && fp >= 1 && fp <= 65535 {
					b.FouPorts = append(b.FouPorts, fp)
				}
			}
		} else {
			ports := parsePorts(strings.ReplaceAll(p, "-", ","))
			if len(ports) > 0 {
				b.Ports = ports
				for _, num := range ports {
					b.RawPorts = append(b.RawPorts, strconv.Itoa(num))
				}
			}
		}
	}
	return b, nil
}

// isBundle reports whether a token field holds a foreign-setup bundle
// (vs a legacy 32-char token, which must keep working as-is).
func isBundle(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, bundlePrefix) || isBackhaulBundle(t) || isGreBackhaulBundle(t)
}

// isBackhaulBundle reports whether s starts with bh1_.
func isBackhaulBundle(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), bundlePrefixBackhaul)
}

// isGreBackhaulBundle reports whether s starts with gh1_.
func isGreBackhaulBundle(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), bundlePrefixGreBackhaul)
}

// applyBundle fills foreign-setup fields from a parsed bundle.
// Bundle is the authoritative Source of Truth for tunnel parameters.
// Explicit body.Ports (from the user's Reverse Ports field) are preserved
// if the bundle itself has no ports segment (e.g. hsh1_...token__fou...).
// body.OrigBundle must be set BEFORE calling applyBundle so runInstaller
// can still pass --bundle to hashem.sh for carrier/FOU configuration.
func applyBundle(body *setupRequest, b setupBundle) {
	if b.Engine != "" {
		body.Engine = b.Engine
	}
	if b.Transport != "" {
		body.Transport = b.Transport
		if b.Engine == "frp" {
			body.FRPTransport = b.Transport
		}
	}
	if b.UDP {
		body.AcceptUDP = true
		body.UDPPort = b.UDPPort
	}
	body.RemotePub = b.IranPub
	body.FrpPort = b.FrpPort

	if b.Engine == "backhaul" {
		body.LocalGre = ""
		body.PeerGre = ""
	} else {
		body.LocalGre = b.ForeignGre
		body.PeerGre = b.IranGre
	}

	// Only override ports from bundle when bundle actually has ports;
	// if the bundle's ports segment was empty, keep what the user typed.
	if len(b.RawPorts) > 0 {
		body.Ports = strings.Join(b.RawPorts, ", ")
	} else if len(b.Ports) > 0 {
		strs := make([]string, len(b.Ports))
		for i, p := range b.Ports {
			strs[i] = strconv.Itoa(p)
		}
		body.Ports = strings.Join(strs, ", ")
	}
	if len(b.FouPorts) >= 2 {
		cfg := loadCarrierConfig()
		cfg.FOUPort1 = b.FouPorts[0]
		cfg.FOUPort2 = b.FouPorts[1]
		cfg.Candidates = []string{"direct", fmt.Sprintf("wss:%d", cfg.WSSPort)}
		_ = saveCarrierConfig(cfg)
		_, _ = runHashemCarrierCmd("set-ports", strconv.Itoa(cfg.FOUPort1), strconv.Itoa(cfg.FOUPort2))
	}
	// Replace body.Token with the inner token (not the full bundle string).
	// The caller must have already saved OrigBundle = body.Token before calling.
	body.Token = b.Token
}
