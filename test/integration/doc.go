//go:build integration

// Package integration runs real git and git-lfs against the server with a
// local S3-compatible store (docker compose up -d s3). TestAccessMatrix runs
// every identity against every action; cells that need parts of the request
// path not yet built are strict expected failures, which fail the test once
// they start passing.
package integration
