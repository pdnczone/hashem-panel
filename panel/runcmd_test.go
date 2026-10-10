package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// withRunner swaps the command runner for one test and resets exec stats.
func withRunner(t *testing.T, r cmdRunner) {
	t.Helper()
	old := runner
	runner = r
	resetExecStats()
	t.Cleanup(func() { runner = old; resetExecStats() })
}

func execStatFor(name string) (execStatJSON, bool) {
	for _, e := range execSnapshot() {
		if e.Command == name {
			return e, true
		}
	}
	return execStatJSON{}, false
}

func TestRunCmdCountsAndOutput(t *testing.T) {
	withRunner(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "bad" {
			return []byte("boom"), errors.New("exit 1")
		}
		return []byte(strings.Join(args, " ")), nil
	})
	out, err := runCmdTimeout(time.Second, "echo", "a", "b")
	if err != nil || string(out) != "a b" {
		t.Fatalf("got %q %v", out, err)
	}
	out, err = runCmdTimeout(time.Second, "bad")
	if err == nil || string(out) != "boom" {
		t.Fatalf("error output must pass through, got %q %v", out, err)
	}
	e, ok := execStatFor("echo")
	if !ok || e.Calls != 1 || e.Errors != 0 || e.CallsLast60s != 1 {
		t.Fatalf("echo stats: %+v", e)
	}
	if b, _ := execStatFor("bad"); b.Errors != 1 {
		t.Fatalf("bad stats: %+v", b)
	}
}

func TestRunCmdTimeout(t *testing.T) {
	withRunner(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	start := time.Now()
	_, err := runCmdTimeout(40*time.Millisecond, "slow")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("expected quick timeout, err=%v after %v", err, time.Since(start))
	}
	e, _ := execStatFor("slow")
	if e.Timeouts != 1 || e.Errors != 1 || e.MaxMs < 30 {
		t.Fatalf("slow stats: %+v", e)
	}
}

func TestRunCmdOutSelectsStdoutOnly(t *testing.T) {
	var got bool
	withRunner(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		got = ctx.Value(stdoutOnlyKey{}) != nil
		return nil, nil
	})
	_, _ = runCmdTimeoutOut(time.Second, "x")
	if !got {
		t.Fatal("runCmdTimeoutOut must mark the context stdout-only")
	}
	_, _ = runCmdTimeout(time.Second, "x")
	if got {
		t.Fatal("runCmdTimeout must not be stdout-only")
	}
}

func TestRunCmdConcurrent(t *testing.T) {
	withRunner(t, func(ctx context.Context, name string, args ...string) ([]byte, error) { return nil, nil })
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = runCmdTimeout(time.Second, "c") }()
	}
	wg.Wait()
	if e, _ := execStatFor("c"); e.Calls != 50 {
		t.Fatalf("calls=%d", e.Calls)
	}
}

func TestRunCmdRealExec(t *testing.T) {
	old := runner
	runner = execRunner
	defer func() { runner = old }()
	out, err := runCmdTimeout(5*time.Second, "sh", "-c", "echo out; echo err 1>&2")
	if err != nil || !strings.Contains(string(out), "out") || !strings.Contains(string(out), "err") {
		t.Fatalf("combined: %q %v", out, err)
	}
	out, _ = runCmdTimeoutOut(5*time.Second, "sh", "-c", "echo out; echo err 1>&2")
	if strings.Contains(string(out), "err") {
		t.Fatalf("stdout-only leaked stderr: %q", out)
	}
}
