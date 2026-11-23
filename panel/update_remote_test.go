package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func withVersion(t *testing.T, v string) {
	t.Helper()
	old := panelVersion
	panelVersion = v
	t.Cleanup(func() { panelVersion = old })
}

// The asked server never downgrades, never crosses channels and takes only a
// release tag.
func TestRemoteUpdateApplyRules(t *testing.T) {
	withVersion(t, "v3.6.0")
	for _, c := range []struct {
		tag, wantErr, wantDetail string
	}{
		{"v3.5.9", "", "already on v3.6.0"},
		{"v3.6.0", "", "already on v3.6.0"},
		{"dev-r900", "different update channels", ""},
		{"v3.7.0/../x", "unexpected release tag", ""},
		{"https://example.com/x", "unexpected release tag", ""},
	} {
		a := remoteUpdateApply(remoteUpdReq{Tag: c.tag}, "test", "127.0.0.1")
		if c.wantErr != "" {
			if a.OK || !strings.Contains(a.Error, c.wantErr) {
				t.Fatalf("%s: %+v", c.tag, a)
			}
			continue
		}
		if !a.OK || a.Updating || a.Detail != c.wantDetail {
			t.Fatalf("%s: %+v", c.tag, a)
		}
	}
	a := remoteUpdateApply(remoteUpdReq{Check: true, Tag: "v9.9.9"}, "test", "127.0.0.1")
	if !a.OK || a.Updating || a.Version != "v3.6.0" {
		t.Fatalf("check: %+v", a)
	}
}

// A linked hub asks over the signed hub channel; an unsigned or unknown one
// gets a bare 404.
func TestMeshUpdateRoute(t *testing.T) {
	newClusterFixture(t, true)
	withVersion(t, "v3.6.0")
	syncHub(t, "203.0.113.9")
	rec := httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/update", remoteUpdReq{ID: "hub-a", Tag: "v3.5.0"}))
	var a remoteUpdAns
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &a) != nil || !a.OK || a.Updating || a.Version != "v3.6.0" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if meshVerify(syncTestSecret, rec.Header(), rec.Body.Bytes(), time.Now()) != nil {
		t.Fatal("the answer is not signed")
	}
	rec = httptest.NewRecorder()
	syncMux().ServeHTTP(rec, syncSigned(t, "/update", remoteUpdReq{ID: "hub-unknown", Check: true}))
	if rec.Code != 404 {
		t.Fatalf("unknown hub: %d", rec.Code)
	}
	r := httptest.NewRequest(http.MethodPost, meshRoutePrefix+"/update", bytes.NewReader([]byte(`{"id":"hub-a","check":true}`)))
	rec = httptest.NewRecorder()
	syncMux().ServeHTTP(rec, r)
	if rec.Code != 404 {
		t.Fatalf("unsigned: %d", rec.Code)
	}
}

type remoteFakes struct {
	mu    sync.Mutex
	calls []string
	vers  map[string]string
}

func fakeRemote(t *testing.T) *remoteFakes {
	t.Helper()
	f := &remoteFakes{vers: map[string]string{"tunnel:0": "v3.5.0", "tunnel:2": "v3.6.0", "tunnel:3": "v3.4.0"}}
	oT, oU, oH, oB := remoteTunnels, remoteUpdCall, remoteHubCall, remoteUpdBack
	t.Cleanup(func() { remoteTunnels, remoteUpdCall, remoteHubCall, remoteUpdBack = oT, oU, oH, oB })
	remoteList.Lock()
	remoteList.at, remoteList.out = time.Time{}, nil
	remoteList.Unlock()
	remoteJob.Lock()
	remoteJob.s = remoteJobState{}
	remoteJob.Unlock()
	remoteTunnels = func() []remoteTarget {
		return []remoteTarget{
			{Key: "tunnel:0", Kind: "foreign", Name: "de", Addr: "198.51.100.1", tunnel: 0},
			{Key: "tunnel:2", Kind: "foreign", Name: "nl", Addr: "198.51.100.2", tunnel: 2},
			{Key: "tunnel:3", Kind: "foreign", Name: "fi", Addr: "198.51.100.3", tunnel: 3},
			{Key: "tunnel:4", Kind: "foreign", Name: "old", Addr: "198.51.100.4", tunnel: 4},
		}
	}
	remoteUpdCall = func(id int, req remoteUpdReq, _ time.Duration) (remoteUpdAns, error) {
		k := "tunnel:" + string(rune('0'+id))
		if id == 4 {
			return remoteUpdAns{}, errRemoteOld
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if req.Check {
			return remoteUpdAns{OK: true, Version: f.vers[k]}, nil
		}
		f.calls = append(f.calls, k+"@"+req.Tag)
		if id == 3 {
			return remoteUpdAns{Error: "panel download failed"}, nil
		}
		return remoteUpdAns{OK: true, Updating: true, Detail: "updated to v3.6.0 — restarting panel", Version: f.vers[k]}, nil
	}
	remoteHubCall = func(h HubPeer, req remoteUpdReq, _ time.Duration) (remoteUpdAns, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, "hub:"+h.ID+"@"+req.Tag)
		return remoteUpdAns{OK: true, Updating: true}, nil
	}
	remoteUpdBack = func(_ context.Context, t remoteTarget, before string) (string, error) {
		return "v3.6.0", nil
	}
	return f
}

func waitRemoteJob(t *testing.T) remoteJobState {
	t.Helper()
	for i := 0; i < 200; i++ {
		if s := remoteJobSnapshot(); !s.Running {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the job did not end")
	return remoteJobState{}
}

// The Update tab lists the hubs and the foreign servers with their versions;
// "Update All" updates those on another version, foreign servers first, and
// one failure does not stop the rest.
func TestRemoteUpdateAll(t *testing.T) {
	newClusterFixture(t, true)
	withVersion(t, "v3.6.0")
	syncHub(t, "203.0.113.9") // hub-a, linked
	meshMu.Lock()
	meshState["hub-a"] = &hubRT{Up: true, LastSeen: time.Now(), Beat: meshBeat{ID: "hub-a", Version: "v3.5.0"}}
	meshMu.Unlock()
	t.Cleanup(func() { meshMu.Lock(); delete(meshState, "hub-a"); meshMu.Unlock() })
	f := fakeRemote(t)

	rec := httptest.NewRecorder()
	handleRemoteUpdateGet(rec, httptest.NewRequest(http.MethodGet, "/api/update/remote", nil))
	var list struct {
		Servers []remoteTarget `json:"servers"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	got := map[string]remoteTarget{}
	for _, s := range list.Servers {
		got[s.Key] = s
	}
	if len(got) != 5 || !got["hub:hub-a"].Differs || got["hub:hub-a"].Version != "v3.5.0" || !got["tunnel:0"].Differs ||
		got["tunnel:2"].Differs || got["tunnel:4"].Reachable || !strings.Contains(got["tunnel:4"].Error, "by hand once") {
		t.Fatalf("list: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	handleRemoteUpdatePost(rec, httptest.NewRequest(http.MethodPost, "/api/update/remote", strings.NewReader(`{"all":true}`)))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	s := waitRemoteJob(t)
	if strings.Join(f.calls, ",") != "tunnel:0@v3.6.0,tunnel:3@v3.6.0,hub:hub-a@v3.6.0" {
		t.Fatalf("calls %v", f.calls)
	}
	states := []string{}
	for _, x := range s.Steps {
		states = append(states, x.Key+"="+x.State)
	}
	if strings.Join(states, ",") != "tunnel:0=done,tunnel:3=failed,hub:hub-a=done" {
		t.Fatalf("steps %v", s.Steps)
	}
	if s.Steps[1].Detail != "panel download failed" || s.Steps[0].Detail != "back on v3.6.0" {
		t.Fatalf("details %+v", s.Steps)
	}

	// one at a time; unknown keys refused
	remoteJob.Lock()
	remoteJob.s.Running = true
	remoteJob.Unlock()
	rec = httptest.NewRecorder()
	handleRemoteUpdatePost(rec, httptest.NewRequest(http.MethodPost, "/api/update/remote", strings.NewReader(`{"keys":["tunnel:0"]}`)))
	if rec.Code == 200 || !strings.Contains(rec.Body.String(), "running already") {
		t.Fatalf("second job: %d %s", rec.Code, rec.Body.String())
	}
	remoteJob.Lock()
	remoteJob.s.Running = false
	remoteJob.Unlock()
	rec = httptest.NewRecorder()
	handleRemoteUpdatePost(rec, httptest.NewRequest(http.MethodPost, "/api/update/remote", strings.NewReader(`{"keys":["tunnel:9"]}`)))
	if rec.Code == 200 {
		t.Fatalf("unknown key: %s", rec.Body.String())
	}
}

// Without the cluster license the hubs are left out of "Update All"; asking
// for one by name is refused like the rest of the cluster.
func TestRemoteUpdateHubsNeedTheCluster(t *testing.T) {
	newClusterFixture(t, false)
	withVersion(t, "v3.6.0")
	syncHub(t, "203.0.113.9")
	meshMu.Lock()
	meshState["hub-a"] = &hubRT{Up: true, LastSeen: time.Now(), Beat: meshBeat{ID: "hub-a", Version: "v3.5.0"}}
	meshMu.Unlock()
	t.Cleanup(func() { meshMu.Lock(); delete(meshState, "hub-a"); meshMu.Unlock() })
	f := fakeRemote(t)
	rec := httptest.NewRecorder()
	handleRemoteUpdatePost(rec, httptest.NewRequest(http.MethodPost, "/api/update/remote", strings.NewReader(`{"keys":["hub:hub-a"]}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("hub without the license: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	handleRemoteUpdatePost(rec, httptest.NewRequest(http.MethodPost, "/api/update/remote", strings.NewReader(`{"all":true}`)))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	waitRemoteJob(t)
	for _, c := range f.calls {
		if strings.HasPrefix(c, "hub:") {
			t.Fatalf("a hub was updated without the license: %v", f.calls)
		}
	}
}

// A server that does not come back is reported, the next one still goes.
func TestRemoteUpdateNotBack(t *testing.T) {
	newClusterFixture(t, true)
	withVersion(t, "v3.6.0")
	fakeRemote(t)
	remoteUpdBack = func(_ context.Context, t remoteTarget, _ string) (string, error) {
		if t.Key == "tunnel:0" {
			return "", errors.New("it did not come back on a new version within 6m0s")
		}
		return "v3.6.0", nil
	}
	ts := remoteTunnels()
	if err := remoteUpdateStart([]remoteTarget{ts[0], ts[1]}, "admin", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	s := waitRemoteJob(t)
	if s.Steps[0].State != "failed" || s.Steps[1].State != "done" {
		t.Fatalf("%+v", s.Steps)
	}
}
