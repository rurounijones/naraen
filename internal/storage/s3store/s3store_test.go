package s3store

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/smithy-go/middleware"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/rurounijones/naraen/internal/oid"
)

var (
	testOID  = oid.OID("ab" + "cd" + strings.Repeat("0", 59) + "1")
	fixedNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
)

func testConfig() aws.Config {
	return aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
		Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
	}
}

func newStore(endpoint string) *Store {
	return newTracedStore(endpoint, tracenoop.NewTracerProvider())
}

func newTracedStore(endpoint string, tp trace.TracerProvider) *Store {
	s := New(testConfig(), endpoint, "acme-lfs", tp)
	s.now = func() time.Time { return fixedNow }
	return s
}

// A HEAD request is traced as a child of the caller's span; pre-signing,
// which sends nothing, is not traced at all.
func TestTracing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "42")
	}))
	defer srv.Close()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	s := newTracedStore(srv.URL, tp)
	ctx, parent := tp.Tracer("test").Start(context.Background(), "batch object")
	if _, err := s.PresignGet(ctx, "1", testOID, "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PresignPut(ctx, "1", testOID, 1, "r"); err != nil {
		t.Fatal(err)
	}
	if n := len(sr.Ended()); n != 0 {
		t.Fatalf("pre-signing made %d spans", n)
	}
	if _, _, err := s.Stat(ctx, "1", testOID); err != nil {
		t.Fatal(err)
	}
	parent.End()
	var head sdktrace.ReadOnlySpan
	for _, sp := range sr.Ended() {
		if sp.Name() == "S3.HeadObject" {
			head = sp
		}
	}
	if head == nil || head.Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Fatalf("no S3.HeadObject span under the caller's: %v", sr.Ended())
	}
}

// signedHeaders returns the X-Amz-SignedHeaders list of a pre-signed URL.
func signedHeaders(t *testing.T, raw string) (*url.URL, []string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u, strings.Split(u.Query().Get("X-Amz-SignedHeaders"), ";")
}

// An upload link signs the length and the SHA-256 the OID names, so S3 takes
// only the exact bytes, and the request ID travels inside the signature.
func TestPresignPut(t *testing.T) {
	s := newStore("http://127.0.0.1:8333")
	link, err := s.PresignPut(context.Background(), "1", testOID, 42, "req-1")
	if err != nil {
		t.Fatal(err)
	}
	u, signed := signedHeaders(t, link.URL)
	if u.Host != "127.0.0.1:8333" || u.Path != "/acme-lfs/1/ab/cd/"+string(testOID) {
		t.Errorf("url = %s, want path-style on the endpoint", link.URL)
	}
	for _, h := range []string{"content-length", "host", "x-amz-checksum-sha256"} {
		if !slices.Contains(signed, h) {
			t.Errorf("signed headers %v lack %s", signed, h)
		}
	}
	q := u.Query()
	if q.Get(RequestIDParam) != "req-1" || q.Get("X-Amz-Expires") != "900" {
		t.Errorf("query = %v", q)
	}
	sum, _ := hex.DecodeString(string(testOID))
	if got := link.Headers["X-Amz-Checksum-Sha256"]; got != base64.StdEncoding.EncodeToString(sum) {
		t.Errorf("checksum header = %q (headers %v)", got, link.Headers)
	}
	for _, h := range []string{"Host", "Content-Length"} {
		if _, ok := link.Headers[h]; ok {
			t.Errorf("%s returned as a client header", h)
		}
	}
	if !link.Expires.Equal(fixedNow.Add(15 * time.Minute)) {
		t.Errorf("expires = %v", link.Expires)
	}
}

// Without an endpoint the link goes to AWS with virtual-hosted addressing.
func TestPresignGet(t *testing.T) {
	s := newStore("")
	link, err := s.PresignGet(context.Background(), "1", testOID, "req-2")
	if err != nil {
		t.Fatal(err)
	}
	u, signed := signedHeaders(t, link.URL)
	if u.Host != "acme-lfs.s3.us-east-1.amazonaws.com" || u.Path != "/1/ab/cd/"+string(testOID) {
		t.Errorf("url = %s", link.URL)
	}
	if !slices.Equal(signed, []string{"host"}) || u.Query().Get(RequestIDParam) != "req-2" {
		t.Errorf("signed %v, query %v", signed, u.Query())
	}
	if len(link.Headers) != 0 {
		t.Errorf("download headers = %v", link.Headers)
	}
}

func TestPresignErrors(t *testing.T) {
	// An endpoint that is not a URL fails endpoint resolution, before signing.
	s := newStore("http://%zz")
	if _, err := s.PresignGet(context.Background(), "1", testOID, "r"); err == nil {
		t.Error("get with a bad endpoint accepted")
	}
	if _, err := s.PresignPut(context.Background(), "1", testOID, 1, "r"); err == nil {
		t.Error("put with a bad endpoint accepted")
	}
}

func TestStat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/acme-lfs/1/ab/cd/" + string(testOID):
			w.Header().Set("Content-Length", "42")
		case "/acme-lfs/1/00/00/" + strings.Repeat("0", 64):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	s := newStore(srv.URL)
	ctx := context.Background()
	if size, found, err := s.Stat(ctx, "1", testOID); err != nil || !found || size != 42 {
		t.Errorf("stored object: %d, %v, %v", size, found, err)
	}
	missing := oid.OID(strings.Repeat("f", 64))
	if size, found, err := s.Stat(ctx, "1", missing); err != nil || found || size != 0 {
		t.Errorf("missing object: %d, %v, %v", size, found, err)
	}
	if _, found, err := s.Stat(ctx, "1", oid.OID(strings.Repeat("0", 64))); err == nil || found {
		t.Errorf("server error: %v, %v", found, err)
	}
}

// The step refuses a request it cannot add the parameter to, rather than
// letting an unlabelled link through.
func TestRequestIDStepRejectsOtherRequests(t *testing.T) {
	_, _, err := requestIDStep("x").HandleBuild(context.Background(), middleware.BuildInput{Request: "not a request"}, nil)
	if err == nil {
		t.Fatal("accepted a non-HTTP request")
	}
}
