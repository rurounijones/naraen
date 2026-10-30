//go:build unix

package main

import (
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRealMainShutsDownOnSignal(t *testing.T) {
	e := devEnv()
	e["NARAEN_SNAPSHOT_FILE"] = snapshotFile(t)
	stdout := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- realMain(env(e), stdout) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stdout.String(), "listening") {
		if time.Now().After(deadline) {
			t.Fatal("server never started listening")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// realMain has installed its handler by now, so this stops the server
	// rather than the test binary.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code = %d, stdout = %s", code, stdout.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
}
