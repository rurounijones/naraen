// Package httpapi is the HTTPS listener: health endpoints, the Batch API and
// the CI token exchange, with webhooks to come.
package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// Readier reports whether the datastore can serve decisions.
type Readier interface{ Ready() bool }

// BatchPattern is the Batch API route. git-lfs-authenticate returns
// https://<host>/{owner}/{repo} as the href and git-lfs appends the rest.
const BatchPattern = "POST /{owner}/{repo}/objects/batch"

// ExchangePattern is the CI token exchange: a workload's OIDC token in, a
// read-only LFS token for the repo out.
const ExchangePattern = "POST /{owner}/{repo}/ci/token"

// Handler returns the HTTPS mux. batch serves the Batch API and exchange the
// CI token exchange; both are built by the caller, so this package needs no
// storage, token or OIDC code.
func Handler(r Readier, batch, exchange http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(BatchPattern, batch)
	mux.Handle(ExchangePattern, exchange)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !r.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return secureHeaders(mux)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, req)
	})
}

// NewServer returns an http.Server with conservative timeouts.
func NewServer(addr string, h http.Handler, cfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// TLSConfig returns a TLS 1.3-only config using cert.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

// SelfSigned creates a throwaway Ed25519 certificate for development.
// Production uses Let's Encrypt. It takes the randomness source so tests can
// make it fail; Ed25519 is used because, unlike ECDSA, its key generation
// honours the supplied reader.
func SelfSigned(random io.Reader, hosts ...string) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("httpapi: generate key: %w", err)
	}
	serial, err := rand.Int(random, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("httpapi: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "naraen-dev"},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(random, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("httpapi: create certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
