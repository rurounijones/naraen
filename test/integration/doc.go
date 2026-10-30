//go:build integration

// Package integration runs real clients against the built server binary, with
// a local S3-compatible store alongside (docker compose up -d s3).
// TestAccessMatrix drives git-lfs-authenticate through real OpenSSH for every
// identity and operation; it moves to git and git-lfs end to end once the
// Batch API exists.
package integration
