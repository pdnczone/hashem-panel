package main

import (
	"strings"
	"testing"
)

func tunedKernel() kernelAudit {
	return kernelAudit{BBREnabled: true, CongestionAlg: "bbr", IPForwarding: true, MSSClamping: true, MSSRule: "1340",
		LimitNOFILE: 1048576, Somaxconn: 65535}
}

func greInputs() doctorInputs {
	st := tunnelStatus{Role: "iran (server)", FrpSvc: "frps", FrpUp: true}
	st.Gre.Exists, st.Gre.Name, st.Gre.PeerIP, st.Gre.Inner = true, "gre-tunnel", "203.0.113.9", "10.10.0.1/30"
	return doctorInputs{st: st, gre: true, innerPeer: "10.10.0.2", publicPeer: "203.0.113.9",
		ping:     pingSummary{Tested: true, Sent: 10, Received: 10, AvgRTT: 40, Jitter: 2, Success: true},
		underlay: pingSummary{Tested: true, Sent: 5, Received: 5, AvgRTT: 39, Success: true},
		mtu:      mtuSummary{Tested: true, Interface: 1380, MaxPacket: 1380, Optimal: 1380, MSS: 1340},
		kernel:   tunedKernel(),
		health:   &tunnelHealthResult{Tunnels: []TunnelHealthEntry{{ID: mainTunnelID, Name: "Tunnel", Engine: "frp", Verdict: VerdictPass}}},
	}
}

func findingTitles(rep *doctorReport) string {
	var t []string
	for _, f := range rep.Findings {
		t = append(t, f.Severity+": "+f.Title)
	}
	return strings.Join(t, "\n")
}

func TestDoctorHealthyGREIsExcellent(t *testing.T) {
	rep := evaluateDoctor(greInputs())
	if len(rep.Findings) != 0 || rep.Score != 100 || rep.Rating != "excellent" {
		t.Fatalf("healthy GRE tunnel: score=%d rating=%s findings:\n%s", rep.Score, rep.Rating, findingTitles(rep))
	}
	if len(rep.Issues) != 0 || len(rep.Recommendations) != 0 || rep.FixAvailable {
		t.Fatalf("no issues and no fix expected: %+v", rep)
	}
}

// The GRE interface MTU is 1380 (hashem.sh). The old doctor probed 1420 and
// 1400 and flagged every healthy GRE server as "fragmented".
func TestDoctorMTUProbeStartsAtInterfaceMTU(t *testing.T) {
	var asked []int
	prev := doctorDFProbe
	doctorDFProbe = func(_ string, payload int) bool { asked = append(asked, payload+28); return payload+28 <= 1380 }
	defer func() { doctorDFProbe = prev }()

	m := executeMTUTest("10.10.0.2", 1380)
	if len(asked) != 1 || asked[0] != 1380 {
		t.Fatalf("healthy path must cost one probe at the interface MTU, asked %v", asked)
	}
	if m.MaxPacket != 1380 || m.Optimal != 1380 || m.MSS != 1340 {
		t.Fatalf("got %+v", m)
	}
}

func TestDoctorMTUSearchFindsPathLimit(t *testing.T) {
	prev := doctorDFProbe
	doctorDFProbe = func(_ string, payload int) bool { return payload+28 <= 1332 }
	defer func() { doctorDFProbe = prev }()

	m := executeMTUTest("10.10.0.2", 1380)
	if m.MaxPacket < 1328 || m.MaxPacket > 1332 || m.MSS != m.Optimal-40 {
		t.Fatalf("path limit 1332: got %+v", m)
	}
	in := greInputs()
	in.mtu = m
	rep := evaluateDoctor(in)
	if !strings.Contains(findingTitles(rep), "Packets of 1380 bytes do not cross the tunnel") {
		t.Fatalf("missing MTU finding:\n%s", findingTitles(rep))
	}

	doctorDFProbe = func(string, int) bool { return false }
	if m := executeMTUTest("10.10.0.2", 1380); m.MaxPacket != 0 || m.Optimal != 0 {
		t.Fatalf("no replies at all is unknown, not tiny: %+v", m)
	}
}

// Backhaul / Bagher servers have no GRE. The old doctor returned 20/100
// "No GRE tunnel configured" for them even when the tunnel worked.
func TestDoctorStandaloneBackhaulIsNotPenalisedForNoGRE(t *testing.T) {
	in := doctorInputs{st: tunnelStatus{Role: "iran (backhaul)", Engine: "backhaul", FrpSvc: "backhaul-server", FrpUp: true},
		kernel: kernelAudit{BBREnabled: true, CongestionAlg: "bbr", LimitNOFILE: 1048576, Somaxconn: 65535},
		health: &tunnelHealthResult{Tunnels: []TunnelHealthEntry{{ID: mainTunnelID, Name: "Tunnel", Engine: "backhaul", Verdict: VerdictPass}}}}
	rep := evaluateDoctor(in)
	if rep.Score != 100 || rep.Rating != "excellent" || len(rep.Findings) != 0 {
		t.Fatalf("working Backhaul: score=%d rating=%s\n%s", rep.Score, rep.Rating, findingTitles(rep))
	}
	if len(rep.Notes) == 0 {
		t.Fatalf("expected a note that GRE checks were skipped")
	}

	in.health.Tunnels[0].Verdict = VerdictFail
	in.health.Tunnels[0].Reason = "control session down"
	in.health.Tunnels[0].Layers.Session = layerFail
	rep = evaluateDoctor(in)
	if rep.Rating != "critical" || !strings.Contains(findingTitles(rep), "control session down") {
		t.Fatalf("failing Backhaul must be critical: %s\n%s", rep.Rating, findingTitles(rep))
	}
}

func TestDoctorIssuesAndRecommendationsStayAligned(t *testing.T) {
	in := greInputs()
	in.kernel = kernelAudit{CongestionAlg: "cubic", LimitNOFILE: 1024, Somaxconn: 4096}
	in.ping.PacketLoss, in.ping.Jitter = 5, 40
	rep := evaluateDoctor(in)
	if len(rep.Issues) != len(rep.Recommendations) || len(rep.Issues) != len(rep.Findings) {
		t.Fatalf("issues %d, recommendations %d, findings %d", len(rep.Issues), len(rep.Recommendations), len(rep.Findings))
	}
	for i, f := range rep.Findings {
		if rep.Issues[i] != f.Title || rep.Recommendations[i] != f.Fix {
			t.Fatalf("finding %d misaligned: %q / %q", i, rep.Issues[i], rep.Recommendations[i])
		}
		if fillTpl(f.TitleTpl, f.Args) != f.Title || fillTpl(f.FixTpl, f.Args) != f.Fix {
			t.Fatalf("template does not rebuild the text: %+v", f)
		}
	}
	if !rep.FixAvailable {
		t.Fatalf("kernel findings are auto-fixable")
	}
}

func TestDoctorTunnelPingVsUnderlay(t *testing.T) {
	// Tunnel address silent, public IP answers: the tunnel is broken, not the route.
	in := greInputs()
	in.health = nil
	in.ping = pingSummary{Tested: true, Sent: 10, PacketLoss: 100}
	rep := evaluateDoctor(in)
	if rep.Rating != "critical" || rep.Score > 45 || !strings.Contains(findingTitles(rep), "does not answer (100% loss)") {
		t.Fatalf("got %s %d\n%s", rep.Rating, rep.Score, findingTitles(rep))
	}
	if strings.Contains(rep.Findings[0].Fix, "does not answer either") {
		t.Fatalf("public IP answered, fix must not blame the route: %s", rep.Findings[0].Fix)
	}
	in.underlay.Success = false
	if rep := evaluateDoctor(in); !strings.Contains(rep.Findings[0].Fix, "203.0.113.9 does not answer either") {
		t.Fatalf("both silent: %s", rep.Findings[0].Fix)
	}

	// Data flows (tunnel health PASS) while ICMP is filtered: minor only.
	in = greInputs()
	in.ping = pingSummary{Tested: true, Sent: 10, PacketLoss: 100}
	if rep := evaluateDoctor(in); rep.Rating == "critical" || rep.Findings[0].Severity != "minor" {
		t.Fatalf("ICMP filtered but data flows: %s\n%s", rep.Rating, findingTitles(rep))
	}
}

func TestDoctorUnconfiguredServer(t *testing.T) {
	rep := evaluateDoctor(doctorInputs{kernel: kernelAudit{CongestionAlg: "cubic"}})
	if rep.Configured || rep.Rating != "unset" || len(rep.Findings) != 0 {
		t.Fatalf("fresh server: %+v", rep)
	}
}

func TestDoctorBagherFindings(t *testing.T) {
	in := doctorInputs{kernel: tunedKernel(), bagher: &doctorBagher{Role: "iran", Active: true, Connected: false, LastError: "Permission denied (publickey)"}}
	rep := evaluateDoctor(in)
	if rep.Rating != "critical" || !strings.Contains(rep.Findings[0].Fix, "Permission denied") {
		t.Fatalf("got %s\n%s / %s", rep.Rating, findingTitles(rep), rep.Findings[0].Fix)
	}
	in.bagher.Connected = true
	if rep := evaluateDoctor(in); rep.Rating != "excellent" {
		t.Fatalf("connected Bagher: %s\n%s", rep.Rating, findingTitles(rep))
	}
}

func TestMSSRuleFrom(t *testing.T) {
	save := "*mangle\n:PREROUTING ACCEPT [0:0]\n-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340\nCOMMIT\n"
	if got := mssRuleFrom(save); got != "1340" {
		t.Fatalf("got %q", got)
	}
	if got := mssRuleFrom("-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n"); got != "pmtu" {
		t.Fatalf("got %q", got)
	}
	if got := mssRuleFrom("*mangle\nCOMMIT\n"); got != "" {
		t.Fatalf("got %q", got)
	}
}
