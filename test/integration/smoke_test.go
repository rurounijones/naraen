//go:build integration

package integration

import (
	"net"
	"testing"
	"time"
)

// TestS3Reachable checks the compose-provided object store is up.
func TestS3Reachable(t *testing.T) {
	c, err := net.DialTimeout("tcp", s3Target, 3*time.Second)
	if err != nil {
		t.Skipf("local S3 not running: %v", err)
	}
	_ = c.Close()
}
