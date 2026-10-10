package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func encodeRescueCodeForTest(t *testing.T, c rescueCode) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return rescueCodePrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeRescueRawForTest(t *testing.T, code string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, rescueCodePrefix))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func muxTestState() rescueState {
	return rescueState{CtrlPort: 31000, Token: "0123456789abcdef0123456789abcdef", Secret: "0123456789abcdef", Ports: []int{1020}}
}

func TestRescueCodeCarriesOriginMux(t *testing.T) {
	for _, want := range []bool{true, false} {
		defer withTempConfigDir(t)()
		c := loadPerfConfig()
		c.TCPMux = boolPtr(want)
		if err := savePerfConfig(c); err != nil {
			t.Fatal(err)
		}
		got, err := rescueDecode(rescueEncode(muxTestState(), "5.75.197.22"))
		if err != nil {
			t.Fatal(err)
		}
		if got.M == nil || *got.M != want {
			t.Fatalf("M = %v, want %v", got.M, want)
		}
	}
}

func TestRescueCodeWithoutMuxDecodesNil(t *testing.T) {
	st := muxTestState()
	raw := rescueCode{V: 1, IP: "5.75.197.22", CPort: st.CtrlPort, Token: st.Token, Secret: st.Secret, Ports: st.Ports}
	code := encodeRescueCodeForTest(t, raw)
	if strings.Contains(decodeRescueRawForTest(t, code), `"m"`) {
		t.Fatal("absent M must be omitted from the code JSON")
	}
	got, err := rescueDecode(code)
	if err != nil {
		t.Fatal(err)
	}
	if got.M != nil {
		t.Fatalf("old code must decode with M nil, got %v", *got.M)
	}
}

func TestRescueEntryTomlMux(t *testing.T) {
	on := rescueEntryFrpcTomlMux("5.75.197.22", 31000, "tok", "sec", []int{1020}, true)
	if !strings.Contains(on, "transport.tcpMux = true") || !strings.Contains(on, "transport.tcpMuxKeepaliveInterval = 30") {
		t.Fatalf("mux=true toml missing tcpMux/keepalive:\n%s", on)
	}
	off := rescueEntryFrpcTomlMux("5.75.197.22", 31000, "tok", "sec", []int{1020}, false)
	if !strings.Contains(off, "transport.tcpMux = false") || strings.Contains(off, "tcpMuxKeepaliveInterval") {
		t.Fatalf("mux=false toml wrong:\n%s", off)
	}
}

func TestRescueEntryTomlLegacyUsesLocalMux(t *testing.T) {
	defer withTempConfigDir(t)()
	c := loadPerfConfig()
	c.TCPMux = boolPtr(true)
	if err := savePerfConfig(c); err != nil {
		t.Fatal(err)
	}
	if got := rescueEntryFrpcToml("5.75.197.22", 31000, "tok", "sec", []int{1020}); !strings.Contains(got, "transport.tcpMux = true") {
		t.Fatalf("old signature must follow local tcpMuxEnabled():\n%s", got)
	}
}
