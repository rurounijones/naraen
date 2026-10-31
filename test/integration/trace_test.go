//go:build integration

package integration

import (
	"path/filepath"
	"testing"
)

// traceSource is TestTracesExported's client address; see sourceFor.
const traceSource = "127.0.0.5"

// A real git lfs push reaches the telemetry backend from the real binary as
// traces: the SSH connection holding the authenticate command, which names
// the token it issued, and the Batch request carrying that token, holding a
// span for the object and that span the S3 request. The Batch request's log
// record is exported in its trace. Together they follow one upload from the
// sign-in to the storage request.
func TestTracesExported(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	bare, _ := e.origin(t)
	dir := e.clone(t, bare, "traced-push")
	content := []byte("traced upload " + e.publicURL + "\n")
	writeFile(t, filepath.Join(dir, "traced.bin"), content)
	for _, args := range [][]string{{"add", "traced.bin"}, {"commit", "-m", "traced"}} {
		if out, err := e.git(t, "", "", dir, nil, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if out, err := e.git(t, "writer", traceSource, dir, nil, "lfs", "push", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	// Shutdown flushes the spans still queued.
	e.stop()
	spans := e.otlp.spans()

	auth := find(spans, "ssh exec", map[string]string{
		"lfs.command": "git-lfs-authenticate", "lfs.operation": "upload", "lfs.repo": "acme/assets", "lfs.repo_id": "1",
	})
	if len(auth) == 0 || auth[0].attrs["lfs.token_id"] == "" {
		t.Fatalf("no authenticate span naming a token (spans: %v)", spans)
	}
	tokenID := auth[0].attrs["lfs.token_id"]
	conn := find(spans, "ssh connection", map[string]string{"lfs.identity": "writer", "lfs.identity_type": "person"})
	if !hasSpan(conn, func(s span) bool { return s.id == auth[0].parent && s.trace == auth[0].trace && s.parent == "" }) {
		t.Errorf("authenticate span %+v is not inside the writer's connection %+v", auth[0], conn)
	}
	// git-lfs tries git-lfs-transfer first; that attempt is traced too.
	if len(find(spans, "ssh exec", map[string]string{"lfs.command": "git-lfs-transfer", "lfs.reason": "unsupported"})) == 0 {
		t.Error("no span for the git-lfs-transfer attempt")
	}

	batch := find(spans, "POST /{owner}/{repo}/objects/batch", map[string]string{
		"lfs.token_id": tokenID, "lfs.identity": "writer", "lfs.operation": "upload", "lfs.links": "1",
		"http.response.status_code": "200",
	})
	if len(batch) != 1 || batch[0].parent != "" || batch[0].attrs["lfs.request_id"] == "" {
		t.Fatalf("no Batch request span carrying token %s (spans: %v)", tokenID, spans)
	}
	object := find(spans, "batch object", map[string]string{"lfs.oid": string(oidFor(content)), "lfs.outcome": "issued"})
	if len(object) != 1 || object[0].parent != batch[0].id || object[0].failed {
		t.Fatalf("object span %+v is not inside the Batch request %s", object, batch[0].id)
	}
	if !hasSpan(spans, func(s span) bool { return s.name == "S3.HeadObject" && s.parent == object[0].id }) {
		t.Errorf("no S3 request inside the object span (spans: %v)", spans)
	}

	exported := e.otlp.records()
	if !hasRecord(exported, map[string]string{
		"msg": "links issued", "trace": batch[0].trace, "request_id": batch[0].attrs["lfs.request_id"], "token_id": tokenID,
	}) {
		t.Errorf("the links issued record is not in the Batch request's trace (exported: %v)", exported)
	}
}

func hasSpan(spans []span, ok func(span) bool) bool {
	for _, s := range spans {
		if ok(s) {
			return true
		}
	}
	return false
}

// hasRecord reports whether any record holds each of want's fields.
func hasRecord(records []map[string]string, want map[string]string) bool {
	for _, rec := range records {
		match := true
		for k, v := range want {
			match = match && rec[k] == v
		}
		if match {
			return true
		}
	}
	return false
}
