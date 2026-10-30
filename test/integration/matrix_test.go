//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/token"
)

// identity is one row of the access matrix.
type identity struct {
	name      string
	kind      datastore.IdentityKind
	active    bool
	inStore   bool            // false: the key is unknown to the datastore
	level     datastore.Level // grant on acme/assets; LevelNone means no grant
	otherOnly bool            // grant on acme/other instead of acme/assets
}

// The rows follow the design's matrix. GitHub roles appear as the levels the
// provider maps them to (triage is read), which the provider's golden tests
// cover. Outside collaborators have no identity and no loaded key, so they
// are the unknown-key row. CI workloads over OIDC are not here yet: the token
// exchange endpoint does not exist.
var matrix = []identity{
	{name: "admin", kind: datastore.KindPerson, active: true, inStore: true, level: datastore.LevelAdmin},
	{name: "maintainer", kind: datastore.KindPerson, active: true, inStore: true, level: datastore.LevelMaintain},
	{name: "writer", kind: datastore.KindPerson, active: true, inStore: true, level: datastore.LevelWrite},
	{name: "reader", kind: datastore.KindPerson, active: true, inStore: true, level: datastore.LevelRead},
	{name: "member-of-other-repo", kind: datastore.KindPerson, active: true, inStore: true, level: datastore.LevelWrite, otherOnly: true},
	{name: "member-without-grant", kind: datastore.KindPerson, active: true, inStore: true},
	{name: "removed-member", kind: datastore.KindPerson, active: false, inStore: true, level: datastore.LevelAdmin},
	{name: "unknown-key", inStore: false},
	{name: "deploy-key-read", kind: datastore.KindDeployKey, active: true, inStore: true, level: datastore.LevelRead},
	{name: "deploy-key-write", kind: datastore.KindDeployKey, active: true, inStore: true, level: datastore.LevelWrite},
	{name: "deploy-key-other-repo", kind: datastore.KindDeployKey, active: true, inStore: true, level: datastore.LevelWrite, otherOnly: true},
}

func (id identity) mayDownload() bool {
	return id.inStore && id.active && !id.otherOnly && id.level >= datastore.LevelRead
}

func (id identity) mayUpload() bool {
	return id.inStore && id.active && !id.otherOnly && id.level >= datastore.LevelWrite
}

// env is the running server and the per-identity client material.
type env struct {
	dir        string
	logs       *syncBuffer
	otlp       *otlpReceiver
	stop       func() // stops the server with SIGTERM and waits for it
	sshPort    int
	publicURL  string
	knownHosts string
	keys       map[string]string // identity name -> private key file
	tokens     *token.Signer     // holds the key the server mints with
}

// TestAccessMatrix runs git-lfs-authenticate, the step git-lfs takes before
// any transfer, as every identity for every operation. An allowed cell must
// get a token for exactly that identity, repo and operation; a denied cell
// must be refused by the server.
func TestAccessMatrix(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	for i, id := range matrix {
		src := sourceFor(i)
		for _, op := range []lfs.Operation{lfs.Upload, lfs.Download} {
			allowed := id.mayDownload()
			if op == lfs.Upload {
				allowed = id.mayUpload()
			}
			t.Run(id.name+"/"+string(op), func(t *testing.T) {
				out, err := e.ssh(t, id.name, src, "git-lfs-authenticate acme/assets "+string(op))
				if !allowed {
					checkDenied(t, err)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				e.checkToken(t, out, id.name, op, "acme/assets")
			})
		}
	}
}

// git-lfs tries git-lfs-transfer first. The server says plainly that it is
// unsupported, rather than refusing, so the client falls back to
// git-lfs-authenticate at once. The answer is the same for an identity with
// no access, so it reveals nothing about grants.
func TestTransferUnsupported(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	for _, as := range []string{"admin", "member-without-grant"} {
		_, err := e.ssh(t, as, transferSource, "git-lfs-transfer acme/assets upload")
		if err == nil || !strings.Contains(err.Error(), "git-lfs-transfer is not supported") {
			t.Fatalf("%s: err = %v", as, err)
		}
	}
}

// Real clients spell the path in several ways. Each normalized spelling, and
// an alias left by a rename, reaches repo 1; the href keeps the normalized
// spelling the client used.
func TestPathVariants(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	for raw, path := range map[string]string{
		"ACME/Assets":     "acme/assets",
		"acme/assets.git": "acme/assets",
		"/acme/assets":    "acme/assets",
		"acme/old-assets": "acme/old-assets",
	} {
		t.Run(raw, func(t *testing.T) {
			out, err := e.ssh(t, "writer", pathSource, "git-lfs-authenticate "+raw+" upload")
			if err != nil {
				t.Fatal(err)
			}
			e.checkToken(t, out, "writer", lfs.Upload, path)
		})
	}
	// A path trick does not parse, so the server rejects the exec request
	// itself, as for any unknown command.
	_, err := e.ssh(t, "writer", pathSource, "git-lfs-authenticate acme/../acme/assets upload")
	if err == nil || !strings.Contains(err.Error(), "exec request failed") {
		t.Fatalf("path trick: err = %v", err)
	}
}

// The audit events reach the telemetry backend from the real binary: a token
// issued, a refused request and a refused key each arrive over OTLP as
// metrics with the labels the alerts use, and as log records, both over OTLP
// and on stdout. The issue's log record names the token by its ID.
func TestAuditEventsExported(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	out, err := e.ssh(t, "writer", auditSource, "git-lfs-authenticate acme/assets upload")
	if err != nil {
		t.Fatal(err)
	}
	claims := e.checkToken(t, out, "writer", lfs.Upload, "acme/assets")
	_, err = e.ssh(t, "reader", auditSource, "git-lfs-authenticate acme/assets upload")
	checkDenied(t, err)
	_, err = e.ssh(t, "unknown-key", auditSource, "git-lfs-authenticate acme/assets download")
	checkDenied(t, err)

	// Shutdown flushes whatever the last export interval had not sent.
	e.stop()
	got := e.otlp.counters(t)
	for point, want := range map[string]int64{
		"lfs.tokens.issued{operation=upload,repo=1,user=writer}":            1,
		"lfs.auth.failures{identity_type=person,reason=insufficient_grant}": 1,
		"lfs.auth.failures{identity_type=unknown,reason=unknown_key}":       1,
	} {
		if got[point] != want {
			t.Errorf("%s = %d, want %d (exported: %v)", point, got[point], want, got)
		}
	}
	logs := e.logs.String()
	for _, want := range []string{`"msg":"token issued"`, `"token_id":"` + claims.ID + `"`, `"msg":"ssh authentication failed"`, `"reason":"insufficient_grant"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("server log lacks %s", want)
		}
	}
	exported := e.otlp.records()
	for _, want := range []map[string]string{
		{"msg": "token issued", "level": "INFO", "token_id": claims.ID, "identity": "writer", "operation": "upload"},
		{"msg": "command refused", "identity": "reader", "reason": "insufficient_grant"},
		{"msg": "ssh authentication failed", "reason": "unknown_key"},
	} {
		if !slices.ContainsFunc(exported, func(rec map[string]string) bool {
			for k, v := range want {
				if rec[k] != v {
					return false
				}
			}
			return true
		}) {
			t.Errorf("no exported log record matches %v (exported: %v)", want, exported)
		}
	}
}

func needSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skipf("ssh not installed: %v", err)
	}
}

// Each identity connects from its own loopback address, as separate people
// would from separate machines, so the server's per-source connection rate
// limit applies at its production defaults without one identity's
// connections counting against the next. Linux routes all of 127.0.0.0/8 to
// the loopback interface.
const (
	transferSource = "127.0.0.2"
	pathSource     = "127.0.0.3"
	auditSource    = "127.0.0.4"
)

func sourceFor(i int) string { return fmt.Sprintf("127.0.0.%d", 10+i) }

// The server's two ways of saying no: SSH refuses the key, or the command
// handler refuses the request. A failure without either came from somewhere
// else, such as a broken harness, and proves nothing about access.
const (
	keyRefused     = "Permission denied (publickey)"
	requestRefused = "request refused"
)

// checkDenied asserts a denied cell: it must fail, and by a server refusal.
func checkDenied(t *testing.T, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Fatal("operation succeeded but must be denied")
	case !strings.Contains(err.Error(), keyRefused) && !strings.Contains(err.Error(), requestRefused):
		t.Fatalf("failed, but not by a server refusal: %v", err)
	}
}

// checkToken asserts an allowed cell's git-lfs-authenticate response: the
// Batch API address for path, a bearer token that verifies for exactly this
// identity, repo ID and operation, and the token's 15 minute lifetime. It
// returns the token's claims.
func (e *env) checkToken(t *testing.T, out, as string, op lfs.Operation, path string) token.Claims {
	t.Helper()
	var resp struct {
		Href      string            `json:"href"`
		Header    map[string]string `json:"header"`
		ExpiresIn int64             `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("response %q: %v", out, err)
	}
	if resp.Href != e.publicURL+"/"+path || resp.ExpiresIn != 900 || len(resp.Header) != 1 {
		t.Errorf("response = %+v", resp)
	}
	tok, ok := strings.CutPrefix(resp.Header["Authorization"], "Bearer ")
	if !ok {
		t.Fatalf("authorization header = %q", resp.Header["Authorization"])
	}
	c, err := e.tokens.Verify(tok, "1", op)
	if err != nil || c.Subject != as {
		t.Errorf("token claims = %+v, %v", c, err)
	}
	return c
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startServer builds and runs the real binary with a snapshot describing the
// matrix, a host key the client trusts explicitly, and every other piece of
// key material from files, as in production.
func startServer(t *testing.T) *env {
	t.Helper()
	e := &env{dir: t.TempDir(), keys: map[string]string{}}

	bin := filepath.Join(e.dir, "naraen")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "github.com/rurounijones/naraen/cmd/naraen")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, out)
	}

	data := datastore.Data{Repos: []datastore.Repo{
		{ID: "1", Path: "acme/assets", Aliases: []string{"acme/old-assets"}},
		{ID: "2", Path: "acme/other"},
	}}
	for _, id := range matrix {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(priv, id.name)
		if err != nil {
			t.Fatal(err)
		}
		e.keys[id.name] = writeFile(t, filepath.Join(e.dir, id.name+".key"), pem.EncodeToMemory(block))
		if !id.inStore {
			continue
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		data.Identities = append(data.Identities, datastore.Identity{ID: id.name, Kind: id.kind, Name: id.name, Active: id.active})
		data.Keys = append(data.Keys, datastore.Key{Fingerprint: ssh.FingerprintSHA256(sshPub), Type: sshPub.Type(), IdentityID: id.name})
		if id.level != datastore.LevelNone {
			repo := "1"
			if id.otherOnly {
				repo = "2"
			}
			data.Grants = append(data.Grants, datastore.Grant{IdentityID: id.name, RepoID: repo, Level: id.level})
		}
	}
	snapJSON, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := writeFile(t, filepath.Join(e.dir, "snapshot.json"), snapJSON)

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostBlock, err := ssh.MarshalPrivateKey(hostPriv, "host")
	if err != nil {
		t.Fatal(err)
	}
	hostKey := writeFile(t, filepath.Join(e.dir, "host.key"), pem.EncodeToMemory(hostBlock))
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := httpapi.SelfSigned(rand.Reader, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := writeFile(t, filepath.Join(e.dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	tlsKey := writeFile(t, filepath.Join(e.dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	// The token key is written here rather than left ephemeral, so the test
	// can verify what the server mints.
	secret := make([]byte, token.MinKeyLength)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	tokenKeys := writeFile(t, filepath.Join(e.dir, "token.keys"), []byte("k1 "+hex.EncodeToString(secret)+"\n"))
	if e.tokens, err = token.NewSigner([]token.Key{{ID: "k1", Secret: secret}}, time.Minute); err != nil {
		t.Fatal(err)
	}

	e.sshPort = freePort(t)
	httpsPort := freePort(t)
	e.publicURL = fmt.Sprintf("https://localhost:%d", httpsPort)
	hostLine := fmt.Sprintf("[127.0.0.1]:%d %s", e.sshPort, ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))
	e.knownHosts = writeFile(t, filepath.Join(e.dir, "known_hosts"), []byte(hostLine))

	e.otlp = newOTLPReceiver(t)
	srv := exec.Command(bin)
	// Every piece of key material is configured, so this is not dev mode.
	srv.Env = []string{
		"NARAEN_OTLP_ENDPOINT=" + e.otlp.URL,
		"NARAEN_SSH_ADDR=" + fmt.Sprintf("127.0.0.1:%d", e.sshPort),
		"NARAEN_HTTPS_ADDR=" + fmt.Sprintf("127.0.0.1:%d", httpsPort),
		"NARAEN_PUBLIC_URL=" + e.publicURL,
		"NARAEN_SNAPSHOT_FILE=" + snapshot,
		"NARAEN_TOKEN_KEYS_FILE=" + tokenKeys,
		"NARAEN_SSH_HOST_KEY_FILE=" + hostKey,
		"NARAEN_TLS_CERT_FILE=" + tlsCert,
		"NARAEN_TLS_KEY_FILE=" + tlsKey,
	}
	logs := &syncBuffer{}
	e.logs = logs
	srv.Stdout, srv.Stderr = logs, logs
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	e.stop = func() {
		// SIGTERM, as an orchestrator stops it, so the server flushes its
		// metrics; a clean exit is part of what is tested.
		once.Do(func() {
			if err := srv.Process.Signal(syscall.SIGTERM); err != nil {
				t.Errorf("stop server: %v", err)
			}
			done := make(chan error, 1)
			go func() { done <- srv.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("server did not stop cleanly: %v", err)
				}
			case <-time.After(20 * time.Second):
				_ = srv.Process.Kill()
				t.Errorf("server did not stop within 20s")
			}
		})
	}
	t.Cleanup(func() {
		e.stop()
		if t.Failed() {
			t.Logf("server log:\n%s", logs.String())
		}
	})

	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", e.sshPort), time.Second)
		if err == nil {
			_ = c.Close()
			return e
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never listened: %v\n%s", err, logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ssh runs command on the server as the named identity, from the source
// address src, with real OpenSSH configured so nothing is accepted blindly:
// only that identity's key, and only the server's known host key. It returns
// stdout, or an error carrying stderr.
func (e *env) ssh(t *testing.T, as, src, command string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-F", "/dev/null", "-p", strconv.Itoa(e.sshPort),
		"-i", e.keys[as], "-o", "BindAddress="+src, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+e.knownHosts,
		"git@127.0.0.1", command)
	cmd.Env = []string{"HOME=" + e.dir, "PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s as %s: %w: %s", command, as, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
