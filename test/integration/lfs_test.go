//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/oid"
	"github.com/rurounijones/naraen/internal/storage"
)

// The S3 service from docker-compose.yml, and the public development
// credentials of test/testdata/seaweedfs/s3.json. The admin identity creates
// buckets and checks what they hold; the server signs with the signer
// identity, which may only read and write objects.
const (
	s3Endpoint     = "http://127.0.0.1:8333"
	s3AdminKey     = "naraen-dev-admin"
	s3AdminSecret  = "naraen-dev-admin-secret-not-for-production" // #nosec G101 -- public dev credential
	s3SignerKey    = "naraen-dev-signer"
	s3SignerSecret = "naraen-dev-signer-secret-not-for-production" // #nosec G101 -- public dev credential
)

func s3Admin() *s3.Client {
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(s3AdminKey, s3AdminSecret, "")}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(s3Endpoint)
		o.UsePathStyle = true
	})
}

// newBucket creates a fresh bucket, so each test starts empty and runs never
// see each other's objects.
func newBucket(t *testing.T) string {
	t.Helper()
	if c, err := net.DialTimeout("tcp", "127.0.0.1:8333", time.Second); err != nil {
		t.Fatalf("S3 is not reachable at %s (start it with `docker compose up -d s3`): %v", s3Endpoint, err)
	} else {
		_ = c.Close()
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	bucket := "acme-lfs-" + hex.EncodeToString(suffix)
	if _, err := s3Admin().CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket %s: %v", bucket, err)
	}
	return bucket
}

// stored reports whether bucket holds id in repoID's folder.
func stored(t *testing.T, bucket, repoID string, id oid.OID) bool {
	t.Helper()
	_, err := s3Admin().HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(storage.ObjectKey(repoID, id)),
	})
	var missing *types.NotFound
	if errors.As(err, &missing) {
		return false
	}
	if err != nil {
		t.Fatalf("head %s: %v", id, err)
	}
	return true
}

func oidFor(content []byte) oid.OID {
	sum := sha256.Sum256(content)
	return oid.OID(hex.EncodeToString(sum[:]))
}

// gitEnv prepares a home directory whose git configuration enables git-lfs
// and trusts the server's certificate, as a developer's would after setup.
func (e *env) gitEnv(t *testing.T) {
	t.Helper()
	e.home = filepath.Join(e.dir, "home")
	if err := os.MkdirAll(e.home, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"lfs", "install", "--skip-repo"},
		{"config", "--global", "user.name", "Test"},
		{"config", "--global", "user.email", "test@example.com"},
		{"config", "--global", "init.defaultBranch", "main"},
		{"config", "--global", "http.sslCAInfo", e.tlsCert},
		{"config", "--global", "lfs.ssh.automultiplex", "false"},
	} {
		if out, err := e.git(t, "", "", e.home, nil, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// git runs git in dir. With an identity, git-lfs reaches the server over
// real OpenSSH with only that identity's key, from source address src.
func (e *env) git(t *testing.T, as, src, dir string, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append([]string{
		"HOME=" + e.home, "PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_LFS_PROGRESS=/dev/null",
	}, extraEnv...)
	if as != "" {
		cmd.Env = append(cmd.Env, "GIT_SSH_COMMAND="+strings.Join([]string{
			"ssh", "-F", "/dev/null", "-i", e.keys[as], "-o", "BindAddress=" + src,
			"-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + e.knownHosts,
		}, " "))
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// origin creates a bare repository whose history holds .lfsconfig, pointing
// git-lfs at the server over SSH, and seed.bin, an LFS object written
// straight into repo 1's folder. It returns the repository and the seed.
func (e *env) origin(t *testing.T) (string, []byte) {
	t.Helper()
	bare := filepath.Join(e.dir, "origin.git")
	work := filepath.Join(e.dir, "seed-work")
	seed := []byte("seed object " + e.publicURL + "\n")
	lfsconfig := fmt.Sprintf("[lfs]\n\turl = ssh://git@127.0.0.1:%d/acme/assets\n\tlocksverify = false\n", e.sshPort)
	steps := []struct {
		dir  string
		args []string
	}{
		{e.dir, []string{"init", "--bare", bare}},
		{e.dir, []string{"init", work}},
		{work, []string{"lfs", "track", "*.bin"}},
	}
	for _, s := range steps {
		if out, err := e.git(t, "", "", s.dir, nil, s.args...); err != nil {
			t.Fatalf("git %v: %v\n%s", s.args, err, out)
		}
	}
	writeFile(t, filepath.Join(work, ".lfsconfig"), []byte(lfsconfig))
	writeFile(t, filepath.Join(work, "seed.bin"), seed)
	// GIT_LFS_SKIP_PUSH leaves the object out of the push; it is put into
	// the bucket directly, so download cells do not depend on any upload.
	for _, args := range [][]string{
		{"add", ".gitattributes", ".lfsconfig", "seed.bin"},
		{"commit", "-m", "seed"},
		{"push", bare, "main"},
	} {
		if out, err := e.git(t, "", "", work, []string{"GIT_LFS_SKIP_PUSH=1"}, args...); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	_, err := s3Admin().PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(e.bucket), Key: aws.String(storage.ObjectKey("1", oidFor(seed))), Body: bytes.NewReader(seed),
	})
	if err != nil {
		t.Fatalf("seed object: %v", err)
	}
	return bare, seed
}

// clone checks out origin without fetching LFS content, so the transfer under
// test is the only one.
func (e *env) clone(t *testing.T, bare, name string) string {
	t.Helper()
	dir := filepath.Join(e.dir, name)
	if out, err := e.git(t, "", "", e.dir, []string{"GIT_LFS_SKIP_SMUDGE=1"}, "clone", bare, dir); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	return dir
}

// TestLFSMatrix runs real git-lfs transfers, through SSH authentication, the
// Batch API and pre-signed URLs against S3, as every identity for every
// operation. An allowed download must deliver the exact bytes and an allowed
// upload must land in the bucket; a denied cell must fail and change nothing.
func TestLFSMatrix(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	bare, seed := e.origin(t)
	for i, id := range matrix {
		src := sourceFor(i)
		t.Run(id.name+"/download", func(t *testing.T) {
			dir := e.clone(t, bare, id.name+"-download")
			out, err := e.git(t, id.name, src, dir, nil, "lfs", "pull")
			got, readErr := os.ReadFile(filepath.Join(dir, "seed.bin"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if id.mayDownload() {
				if err != nil || !bytes.Equal(got, seed) {
					t.Fatalf("download failed: %v\n%s", err, out)
				}
				return
			}
			if err == nil || bytes.Equal(got, seed) {
				t.Fatalf("download must be denied, got %q\n%s", got, out)
			}
		})
		t.Run(id.name+"/upload", func(t *testing.T) {
			dir := e.clone(t, bare, id.name+"-upload")
			content := []byte("uploaded by " + id.name + " " + e.publicURL + "\n")
			writeFile(t, filepath.Join(dir, "new.bin"), content)
			for _, args := range [][]string{{"add", "new.bin"}, {"commit", "-m", "new"}} {
				if out, err := e.git(t, "", "", dir, nil, args...); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			out, err := e.git(t, id.name, src, dir, nil, "lfs", "push", "origin", "main")
			landed := stored(t, e.bucket, "1", oidFor(content))
			if id.mayUpload() {
				if err != nil || !landed {
					t.Fatalf("upload failed (stored %v): %v\n%s", landed, err, out)
				}
				return
			}
			if err == nil || landed {
				t.Fatalf("upload must be denied (stored %v)\n%s", landed, out)
			}
		})
	}
}

// batchAs authenticates as the identity over SSH and posts a batch for one
// object with the token, as git-lfs does. It returns the decoded response.
func (e *env) batchAs(t *testing.T, as, src string, op lfs.Operation, id oid.OID, size int64) batchResponse {
	t.Helper()
	out, err := e.ssh(t, as, src, "git-lfs-authenticate acme/assets "+string(op))
	if err != nil {
		t.Fatal(err)
	}
	var auth struct {
		Href   string            `json:"href"`
		Header map[string]string `json:"header"`
	}
	if err := json.Unmarshal([]byte(out), &auth); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"operation":%q,"transfers":["basic"],"objects":[{"oid":%q,"size":%d}]}`, op, id, size)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, auth.Href+"/objects/batch", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", auth.Header["Authorization"])
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	resp, err := e.httpClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var br batchResponse
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&br) != nil || len(br.Objects) != 1 {
		t.Fatalf("batch: status %d, %+v", resp.StatusCode, br)
	}
	return br
}

type batchResponse struct {
	Objects []struct {
		Actions map[string]struct {
			Href   string            `json:"href"`
			Header map[string]string `json:"header"`
		} `json:"actions"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	} `json:"objects"`
}

// httpClient trusts only the server's certificate.
func (e *env) httpClient(t *testing.T) *http.Client {
	t.Helper()
	pemBytes, err := os.ReadFile(e.tlsCert)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
}

// put sends body to an upload link with its headers and returns the status.
func put(t *testing.T, href string, header map[string]string, body []byte) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, href, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// An upload link from the server is good only for the bytes its OID names:
// S3 refuses other bytes of the same length (the signed SHA-256), any other
// length (the signed Content-Length), and the link without its headers. Once
// the object is stored, the server issues no further upload link for it, and
// a download of an object that was never stored is an object error.
func TestUploadIntegrity(t *testing.T) {
	needSSH(t)
	e := startServer(t)
	content := []byte("integrity check " + e.publicURL + "\n")
	id := oidFor(content)
	br := e.batchAs(t, "writer", sourceFor(0), lfs.Upload, id, int64(len(content)))
	up, ok := br.Objects[0].Actions["upload"]
	if !ok {
		t.Fatalf("no upload action: %+v", br)
	}
	tampered := bytes.ToUpper(content)
	for name, tt := range map[string]struct {
		header map[string]string
		body   []byte
		want   int
	}{
		"other bytes, same length": {up.Header, tampered, http.StatusBadRequest},
		"one byte longer":          {up.Header, append(append([]byte{}, content...), '!'), http.StatusForbidden},
		"without the headers":      {nil, content, http.StatusForbidden},
	} {
		if got := put(t, up.Href, tt.header, tt.body); got != tt.want {
			t.Errorf("%s: status %d, want %d", name, got, tt.want)
		}
	}
	if stored(t, e.bucket, "1", id) {
		t.Fatal("a rejected upload was stored")
	}
	if got := put(t, up.Href, up.Header, content); got != http.StatusOK {
		t.Fatalf("genuine upload: status %d", got)
	}
	if !stored(t, e.bucket, "1", id) {
		t.Fatal("genuine upload not stored")
	}
	if stored(t, e.bucket, "2", id) {
		t.Fatal("upload to repo 1 landed in the folder of repo 2")
	}
	again := e.batchAs(t, "writer", sourceFor(1), lfs.Upload, id, int64(len(content)))
	if again.Objects[0].Actions != nil {
		t.Errorf("upload link issued for a stored object: %+v", again.Objects[0])
	}
	missing := e.batchAs(t, "reader", sourceFor(2), lfs.Download, oidFor([]byte("never stored")), 12)
	if missing.Objects[0].Error == nil || missing.Objects[0].Error.Code != http.StatusNotFound {
		t.Errorf("download of a missing object: %+v", missing.Objects[0])
	}
	logs := e.logs.String()
	if strings.Count(logs, `"msg":"links issued"`) != 3 {
		t.Errorf("want one links-issued record per batch:\n%s", logs)
	}
}
