//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
)

// pendingRequestPath explains every expected failure in the matrix. When the
// handlers exist, these cells start passing, expectFailure turns that into a
// test failure, and the mark must be removed.
const pendingRequestPath = "git-lfs-authenticate is a refuse-all placeholder and the Batch API and presigner are not built"

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
	sshPort    int
	knownHosts string
	caFile     string
	keys       map[string]string // identity name -> private key file
}

func TestAccessMatrix(t *testing.T) {
	for _, tool := range []string{"git", "git-lfs", "ssh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed: %v", tool, err)
		}
	}
	e := startServer(t)

	// Every download needs an object on the server, uploaded by an identity
	// that may upload. Until uploads work this fails, and with it every
	// allowed download, which is expected.
	repo := e.newRepo(t, "seed")
	seedErr := e.lfs(t, repo, "admin", seedSource, "push", "--all", "origin")

	for i, id := range matrix {
		src := sourceFor(i)
		t.Run(id.name+"/upload", func(t *testing.T) {
			repo := e.newRepo(t, id.name+"-up")
			err := e.lfs(t, repo, id.name, src, "push", "--all", "origin")
			check(t, id.mayUpload(), err)
		})
		t.Run(id.name+"/download", func(t *testing.T) {
			repo := e.newRepo(t, id.name+"-down")
			if err := os.RemoveAll(filepath.Join(repo, ".git", "lfs", "objects")); err != nil {
				t.Fatal(err)
			}
			err := e.lfs(t, repo, id.name, src, "fetch", "--all", "origin")
			if err != nil && seedErr != nil {
				err = fmt.Errorf("%w (seed upload also failed: %w)", err, seedErr)
			}
			check(t, id.mayDownload(), err)
		})
	}
}

// Each identity connects from its own loopback address, as separate people
// would from separate machines, so the server's per-source connection rate
// limit applies at its production defaults without one identity's
// connections counting against the next. Linux routes all of 127.0.0.0/8 to
// the loopback interface. The seed upload is admin on a second machine.
const seedSource = "127.0.0.2"

func sourceFor(i int) string { return fmt.Sprintf("127.0.0.%d", 10+i) }

// The server's two ways of saying no: SSH refuses the key, or the command
// handler refuses the request. A failure without either came from somewhere
// else, such as a broken harness, and proves nothing about access.
const (
	keyRefused     = "Permission denied (publickey)"
	requestRefused = "request refused"
)

// check asserts a matrix cell. Denials are real assertions, though until the
// request path exists every command is refused, so they hold for that reason
// too. Allowed cells are expected failures until then.
func check(t *testing.T, allowed bool, err error) {
	t.Helper()
	if !allowed {
		switch {
		case err == nil:
			t.Fatal("operation succeeded but must be denied")
		case !strings.Contains(err.Error(), keyRefused) && !strings.Contains(err.Error(), requestRefused):
			t.Fatalf("failed, but not by a server refusal: %v", err)
		}
		return
	}
	expectFailure(t, pendingRequestPath, requestRefused, err)
}

// expectFailure skips a cell that fails as expected, with marker in its
// error. It fails a cell that unexpectedly passes, so the mark cannot outlive
// its reason, and one that fails some other way, so a broken harness cannot
// hide behind the mark.
func expectFailure(t *testing.T, reason, marker string, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Fatalf("now passes; remove the expected-failure mark (%s)", reason)
	case !strings.Contains(err.Error(), marker):
		t.Fatalf("expected failure (%s) failed for another reason: %v", reason, err)
	}
	t.Skipf("expected failure (%s): %v", reason, err)
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
// matrix, a host key the client trusts explicitly, and a certificate the
// client is told to trust, so nothing is accepted blindly.
func startServer(t *testing.T) *env {
	t.Helper()
	e := &env{dir: t.TempDir(), keys: map[string]string{}}

	bin := filepath.Join(e.dir, "naraen")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "github.com/rurounijones/naraen/cmd/naraen")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, out)
	}

	data := datastore.Data{Repos: []datastore.Repo{
		{ID: "1", Path: "acme/assets"},
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
	e.caFile = writeFile(t, filepath.Join(e.dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	tlsKey := writeFile(t, filepath.Join(e.dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	e.sshPort = freePort(t)
	httpsPort := freePort(t)
	hostLine := fmt.Sprintf("[127.0.0.1]:%d %s", e.sshPort, ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))
	e.knownHosts = writeFile(t, filepath.Join(e.dir, "known_hosts"), []byte(hostLine))

	ctx, cancel := context.WithCancel(context.Background())
	srv := exec.CommandContext(ctx, bin)
	srv.Env = []string{
		"NARAEN_DEV=true", // the token key is still ephemeral
		"NARAEN_SSH_ADDR=" + fmt.Sprintf("127.0.0.1:%d", e.sshPort),
		"NARAEN_HTTPS_ADDR=" + fmt.Sprintf("127.0.0.1:%d", httpsPort),
		"NARAEN_SNAPSHOT_FILE=" + snapshot,
		"NARAEN_SSH_HOST_KEY_FILE=" + hostKey,
		"NARAEN_TLS_CERT_FILE=" + e.caFile,
		"NARAEN_TLS_KEY_FILE=" + tlsKey,
	}
	logs := &strings.Builder{}
	srv.Stdout, srv.Stderr = logs, logs
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = srv.Wait()
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

// git runs git in dir with a hermetic configuration.
func (e *env) git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = e.baseEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func (e *env) baseEnv() []string {
	return []string{
		"HOME=" + e.dir,
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=matrix", "GIT_AUTHOR_EMAIL=matrix@example.com",
		"GIT_COMMITTER_NAME=matrix", "GIT_COMMITTER_EMAIL=matrix@example.com",
	}
}

// newRepo creates a repository with one committed LFS object, a local bare
// remote, and lfs.url pointing at the server over SSH, as .lfsconfig would.
func (e *env) newRepo(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(e.dir, name)
	remote := dir + ".git"
	for _, d := range []string{dir, remote} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.git(t, remote, "init", "-q", "--bare")
	e.git(t, dir, "init", "-q", "-b", "main")
	e.git(t, dir, "lfs", "install", "--local")
	e.git(t, dir, "config", "lfs.url", fmt.Sprintf("ssh://git@127.0.0.1:%d/acme/assets", e.sshPort))
	// The locks API is not implemented; .lfsconfig disables verification.
	e.git(t, dir, "config", "lfs.locksverify", "false")
	e.git(t, dir, "config", "lfs.transfer.maxretries", "1")
	e.git(t, dir, "config", "http.sslCAInfo", e.caFile)
	e.git(t, dir, "remote", "add", "origin", remote)
	e.git(t, dir, "lfs", "track", "*.bin")
	// The same content in every repo, so every download asks for the seeded object.
	writeFile(t, filepath.Join(dir, "asset.bin"), []byte("naraen access matrix object\n"))
	e.git(t, dir, "add", ".gitattributes", "asset.bin")
	e.git(t, dir, "commit", "-q", "-m", "asset")
	return dir
}

// lfs runs a git lfs subcommand in repo as the named identity, connecting
// from the source address src, and returns its error, with output, if it
// fails.
func (e *env) lfs(t *testing.T, repo, as, src string, args ...string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"lfs"}, args...)...)
	cmd.Dir = repo
	sshCmd := fmt.Sprintf("ssh -F /dev/null -i %s -o BindAddress=%s -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s",
		e.keys[as], src, e.knownHosts)
	cmd.Env = append(e.baseEnv(), "GIT_SSH_COMMAND="+sshCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git lfs %s as %s: %w: %s", strings.Join(args, " "), as, err, strings.TrimSpace(string(out)))
	}
	return nil
}
