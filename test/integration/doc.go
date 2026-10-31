//go:build integration

// Package integration runs real clients against the built server binary, with
// a local S3-compatible store alongside (docker compose run --rm s3-init),
// configured to check signatures. TestLFSMatrix drives git and git-lfs end to end, over
// real OpenSSH, the Batch API and pre-signed URLs, for every identity and
// operation; TestAccessMatrix checks the tokens git-lfs-authenticate issues
// on the way; TestUploadIntegrity proves S3 honours the signed checksum and
// length.
package integration
