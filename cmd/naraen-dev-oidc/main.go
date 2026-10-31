// Command naraen-dev-oidc is a development OIDC issuer that stands in for
// GitHub Actions in the local stack (docker-compose.yml's oidc service), so
// the CI token exchange can be used and scanned end to end. It is never
// released and must never be trusted outside development: its signing key is
// committed in test/testdata/devkeys, and it mints a token for any repository
// to anyone who asks.
//
// It follows GitHub's shape. A CI job asks
//
//	GET /token?audience=<aud>&repository_id=<id>&repository=<owner/name>
//
// and gets {"value": "<JWT>"}: an ES256 token with the claims GitHub sets
// that naraen reads (iss, aud, sub, repository, repository_id, ref, iat, nbf,
// exp, jti). The JWKS is served at /.well-known/jwks and named by
// /.well-known/openid-configuration, as an issuer's are, although naraen
// never fetches it: the trust entry in the datastore carries the keys.
package main

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// KeyID names the signing key in token headers and the JWKS.
const KeyID = "naraen-dev-oidc"

// tokenTTL is how long a minted token is valid: short, like GitHub's, but
// long enough to outlast a DAST scan that reuses one token.
const tokenTTL = 10 * time.Minute

var b64 = base64.RawURLEncoding

// exit is replaced in tests.
var exit = os.Exit

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	exit(report(run(ctx, os.Getenv, os.ReadFile, net.Listen, log), log))
}

// report logs err, if any, and returns the process exit code.
func report(err error, log *slog.Logger) int {
	if err == nil {
		return 0
	}
	log.Error("fatal", "error", err)
	return 1
}

// run serves the issuer until ctx is done.
func run(ctx context.Context, getenv func(string) string, readFile func(string) ([]byte, error),
	listen func(network, addr string) (net.Listener, error), log *slog.Logger,
) error {
	name := getenv("NARAEN_DEV_OIDC_ISSUER")
	if name == "" {
		return errors.New("NARAEN_DEV_OIDC_ISSUER is required")
	}
	raw, err := readFile(getenv("NARAEN_DEV_OIDC_KEY_FILE"))
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	key, err := ParseKey(raw)
	if err != nil {
		return err
	}
	ln, err := listen("tcp", cmp.Or(getenv("NARAEN_DEV_OIDC_ADDR"), ":8080"))
	if err != nil {
		return err
	}
	iss := &issuer{url: name, key: key, now: time.Now, log: log}
	srv := &http.Server{Handler: iss.handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.WithoutCancel(ctx))
	}()
	log.InfoContext(ctx, "listening", "addr", ln.Addr().String(), "issuer", name)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ParseKey reads a PKCS #8 PEM private key, which must be ECDSA P-256.
func ParseKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("key: want an ECDSA P-256 key")
	}
	return ec, nil
}

// JWKS returns the JWK Set holding pub, as the issuer serves it and as a
// trust entry carries it.
func JWKS(pub *ecdsa.PublicKey) ([]byte, error) {
	// Bytes is the uncompressed point: 0x04, then x and y.
	point, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": KeyID,
		"x": b64.EncodeToString(point[1:33]), "y": b64.EncodeToString(point[33:]),
	}}})
}

type issuer struct {
	url string
	key *ecdsa.PrivateKey
	now func() time.Time
	log *slog.Logger
}

func (i *issuer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                i.url,
			"jwks_uri":                              i.url + "/.well-known/jwks",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
			"claims_supported":                      []string{"sub", "aud", "exp", "iat", "iss", "jti", "nbf", "ref", "repository", "repository_id"},
		})
	})
	mux.HandleFunc("GET /.well-known/jwks", func(w http.ResponseWriter, _ *http.Request) {
		// ParseKey accepted only P-256 keys, whose encoding cannot fail.
		jwks, _ := JWKS(&i.key.PublicKey)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})
	mux.HandleFunc("GET /token", i.token)
	return mux
}

// token mints a token for the repository the query names.
func (i *issuer) token(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	aud, id, repo := q.Get("audience"), q.Get("repository_id"), q.Get("repository")
	if aud == "" || id == "" || repo == "" {
		http.Error(w, "audience, repository_id and repository are required", http.StatusBadRequest)
		return
	}
	now := i.now()
	tok, err := i.sign(map[string]any{
		"iss": i.url, "aud": aud, "sub": "repo:" + repo + ":ref:refs/heads/main",
		"repository": repo, "repository_id": id, "ref": "refs/heads/main",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(tokenTTL).Unix(), "jti": rand.Text(),
	})
	if err != nil {
		i.log.ErrorContext(r.Context(), "sign failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	i.log.InfoContext(r.Context(), "token minted", "repository", repo, "repository_id", id, "audience", aud)
	writeJSON(w, map[string]string{"value": tok})
}

// sign returns claims as a compact ES256 JWS.
func (i *issuer) sign(claims map[string]any) (string, error) {
	// Maps of strings and numbers always marshal.
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": KeyID, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
