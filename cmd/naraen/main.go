// Command naraen is the S3 LFS server: an SSH listener for authentication and an
// HTTPS listener for the Batch API.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/batch"
	"github.com/rurounijones/naraen/internal/config"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
	"github.com/rurounijones/naraen/internal/oidc"
	"github.com/rurounijones/naraen/internal/provider"
	"github.com/rurounijones/naraen/internal/provider/github"
	"github.com/rurounijones/naraen/internal/sshd"
	"github.com/rurounijones/naraen/internal/storage/s3store"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/token"
)

// exit is replaced in tests.
var exit = os.Exit

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

// shutdownTimeout bounds the graceful HTTPS shutdown.
const shutdownTimeout = 10 * time.Second

func main() {
	exit(realMain(os.Getenv, os.Stdout))
}

// realMain runs the server until SIGINT or SIGTERM and returns the exit code.
func realMain(getenv config.Getenv, stdout io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, getenv, rand.Reader, log); err != nil {
		log.Error("fatal", "error", err)
		return 1
	}
	return 0
}

// run serves until ctx is done or a listener fails. random supplies the
// entropy for ephemeral development key material.
func run(ctx context.Context, getenv config.Getenv, random io.Reader, log *slog.Logger) error {
	cfg, err := config.Load(getenv, os.ReadFile)
	if err != nil {
		return err
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()

	tel, err := telemetry.New(ctx, telemetry.Export{Endpoint: cfg.OTLPEndpoint, Headers: cfg.OTLPHeaders, Version: version})
	if err != nil {
		return err
	}
	// Telemetry's own failures are reported to the local log only, never
	// back into the pipeline that failed.
	local := log
	otel.SetErrorHandler(telemetry.ErrorHandler(local))
	defer flushTelemetry(tel, local)
	log = slog.New(tel.LogHandler(local.Handler()))
	rec := telemetry.NewRecorder(tel.Meter)
	if cfg.OTLPEndpoint == "" {
		log.WarnContext(ctx, "metrics and logs are not exported: NARAEN_OTLP_ENDPOINT is not set")
	}

	store := datastore.NewStore(cfg.SnapshotMaxAge, datastore.DefaultLimits)
	telemetry.ObserveDatastoreAge(tel.Meter, store.Age)
	if cfg.SnapshotFile != "" {
		if err := loadSnapshot(store, cfg.SnapshotFile, cfg.Dev); err != nil {
			return err
		}
		if !cfg.Dev {
			log.WarnContext(ctx, "datastore loaded from a snapshot file: no provider keeps it in step with GitHub", "file", cfg.SnapshotFile)
		}
	}
	// With neither a snapshot file nor a provider the server stays not-ready
	// and refuses everything.
	if cfg.GitHub != nil {
		p, err := githubProvider(*cfg.GitHub)
		if err != nil {
			return err
		}
		go provider.Run(ctx, p, store, cfg.GitHub.SyncInterval, rec, log)
	}

	if cfg.Dev {
		log.WarnContext(ctx, "development mode: key material that is not configured (SSH host key, TLS certificate, signing key) is ephemeral")
	}
	hostKey, err := loadHostKey(cfg, random)
	if err != nil {
		return err
	}
	cert, err := loadCertificate(cfg, random)
	if err != nil {
		return err
	}
	tokens, err := loadTokenSigner(cfg, random)
	if err != nil {
		return err
	}
	authorizer := authz.New(store)
	batchHandler := batch.Unconfigured()
	if cfg.Bucket != "" {
		objects, err := loadStorage(ctx, cfg.S3Endpoint, cfg.Bucket)
		if err != nil {
			return err
		}
		batchHandler = &batch.Handler{
			Store: store, Authz: authorizer, Tokens: tokens,
			Objects: objects, Rec: rec, Log: log, Rand: rand.Reader,
		}
	} else {
		log.WarnContext(ctx, "development mode: no bucket configured (NARAEN_S3_BUCKET), so the Batch API answers 503")
	}
	exchange := &oidc.Exchange{
		Store: store, Authz: authorizer, Tokens: tokens, Base: cfg.PublicURL,
		Rec: rec, Log: log, Now: time.Now,
	}
	// The webhook is optional: without it, access removed on GitHub stops at
	// the next full sync instead of at once.
	var webhook http.Handler
	if len(cfg.WebhookSecret) > 0 {
		webhook = &github.WebhookHandler{Secret: cfg.WebhookSecret, Store: store, Log: log}
	}
	httpSrv := httpapi.NewServer(cfg.HTTPSAddr, httpapi.Handler(store, batchHandler, exchange, webhook), httpapi.TLSConfig(cert))

	sshLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.SSHAddr)
	if err != nil {
		return fmt.Errorf("ssh listen: %w", err)
	}
	sshCfg := sshd.NewServerConfig(hostKey, authorizer)
	authenticate := sshd.NewAuthenticator(authorizer, tokens, cfg.PublicURL, rec)

	// Both servers report here when they stop; ErrServerClosed and a nil
	// Serve result are the normal shutdown outcomes and are filtered below.
	errc := make(chan error, 2)
	go func() { errc <- sshd.Serve(ctx, sshLn, sshCfg, sshLimits(cfg), authenticate, rec, log) }()
	go func() { errc <- httpSrv.ListenAndServeTLS("", "") }()
	log.InfoContext(ctx, "listening", "version", version, "ssh", cfg.SSHAddr, "https", cfg.HTTPSAddr, "public_origin", cfg.PublicURL)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return errors.Join(runErr, httpSrv.Shutdown(shutdown))
}

// sshLimits returns the SSH listener's limits: the defaults, with any
// configured connection-rate overrides applied.
func sshLimits(cfg config.Config) sshd.Limits {
	lim := sshd.DefaultLimits
	if cfg.SSHConnBurst > 0 {
		lim.ConnBurst = cfg.SSHConnBurst
	}
	if cfg.SSHConnInterval > 0 {
		lim.ConnInterval = cfg.SSHConnInterval
	}
	return lim
}

// loadHostKey reads the SSH host key, or in dev mode without one generates an
// ephemeral key.
func loadHostKey(cfg config.Config, random io.Reader) (ssh.Signer, error) {
	if cfg.SSHHostKeyFile != "" {
		pem, err := os.ReadFile(cfg.SSHHostKeyFile) // #nosec G304 -- operator-supplied path
		if err != nil {
			return nil, fmt.Errorf("host key: %w", err)
		}
		s, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("host key: %w", err)
		}
		if fp := ssh.FingerprintSHA256(s.PublicKey()); !cfg.Dev && fp == devHostKeyFingerprint {
			return nil, fmt.Errorf("host key: %s is the public development host key, accepted only when NARAEN_DEV=true", fp)
		}
		return s, nil
	}
	_, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	// NewSignerFromKey cannot fail for an Ed25519 key.
	s, _ := ssh.NewSignerFromKey(priv)
	return s, nil
}

// loadCertificate reads the TLS key pair, or in dev mode without one creates a
// self-signed certificate.
func loadCertificate(cfg config.Config, random io.Reader) (tls.Certificate, error) {
	if cfg.TLSCertFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("tls certificate: %w", err)
		}
		if sum := sha256.Sum256(c.Certificate[0]); !cfg.Dev && hex.EncodeToString(sum[:]) == devCertSHA256 {
			return tls.Certificate{}, errors.New("tls certificate: this is the public development certificate, accepted only when NARAEN_DEV=true")
		}
		return c, nil
	}
	return httpapi.SelfSigned(random, "localhost")
}

// loadTokenSigner builds the token signer from the configured keys, or in dev
// mode without a key file from an ephemeral key, so tokens die with the
// process.
func loadTokenSigner(cfg config.Config, random io.Reader) (*token.Signer, error) {
	keys := cfg.TokenKeys
	if len(keys) == 0 {
		secret := make([]byte, token.MinKeyLength)
		if _, err := io.ReadFull(random, secret); err != nil {
			return nil, fmt.Errorf("token key: %w", err)
		}
		keys = []token.Key{{ID: "dev", Secret: secret}}
	}
	s, err := token.NewSigner(keys, cfg.TokenTTL)
	if err != nil {
		return nil, fmt.Errorf("token key: %w", err)
	}
	return s, nil
}

// devKeyFingerprints are the development keys committed in
// test/testdata/devkeys. Their private halves are public, so a snapshot that
// lists either is refused outside dev mode: pointing a production server at
// the dev snapshot must not hand upload rights to anyone who reads the repo.
// TestDevSnapshotFixture keeps this list in step with the key files.
var devKeyFingerprints = []string{
	"SHA256:3gzqoh0HmPR7wXovKf0R5jO41Aoyu2f06LgDx8LQY8s", // writer
	"SHA256:nY3kj39hB+G2rfiakn6x9jIZiid3G3onHOpaJTzBVvo", // reader
}

// devHostKeyFingerprint and devCertSHA256 identify the development SSH host
// key and TLS certificate committed beside the dev keys, so that compose
// keeps one host identity across restarts and clients can trust it once.
// Their private halves are public, so outside dev mode either one is
// refused: a production server using them could be impersonated by anyone
// who reads the repo. TestDevServerIdentity keeps them in step with the files.
const (
	devHostKeyFingerprint = "SHA256:ece12yWlKcAsYMpwTau1lNvkQ5prkwdrUoIov2UX3vc"
	devCertSHA256         = "1e48fa9e62e5570c61c70b28567195cf5d8ff50fda5dec5d9ba9fffc350130e2"
)

// devOIDCKeyX is the x coordinate (base64url) of the development OIDC issuer's
// signing key, test/testdata/devkeys/oidc.key, which cmd/naraen-dev-oidc signs
// CI tokens with. Its private half is public, so a snapshot whose trust
// entries hold it is refused outside dev mode: anyone could mint CI tokens it
// accepts. TestDevSnapshotFixture keeps it in step with the key file.
const devOIDCKeyX = "JvNOU9RbmLBeQroGvqHsQE2Ms6JLC5rqhgU4Z1UKqLM" // gitleaks:allow -- a public key coordinate, not a secret

// trustsDevOIDCKey reports whether any trust entry's JWKS holds the
// development OIDC key.
func trustsDevOIDCKey(snap *datastore.Snapshot) bool {
	for _, t := range snap.Trusts() {
		var set struct {
			Keys []struct {
				X string `json:"x"`
			} `json:"keys"`
		}
		// ParseSnapshot has already checked that every JWKS parses.
		_ = json.Unmarshal([]byte(t.JWKS), &set)
		for _, k := range set.Keys {
			if k.X == devOIDCKeyX {
				return true
			}
		}
	}
	return false
}

func loadSnapshot(store *datastore.Store, path string, dev bool) error {
	// Freshness counts from before the file is read, as for any sync.
	start := store.StartSync()
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return fmt.Errorf("snapshot file: %w", err)
	}
	defer f.Close()
	snap, err := datastore.ParseSnapshot(f)
	if err != nil {
		return err
	}
	if !dev {
		for _, fp := range devKeyFingerprints {
			if _, ok := snap.KeyHolder(fp); ok {
				return fmt.Errorf("snapshot file: lists the public development key %s, which is accepted only when NARAEN_DEV=true", fp)
			}
		}
		if trustsDevOIDCKey(snap) {
			return errors.New("snapshot file: trusts the public development OIDC key, which is accepted only when NARAEN_DEV=true")
		}
	}
	return store.Swap(start, snap)
}

// flushTelemetry pushes the metrics and logs recorded since the last export. A
// collector that cannot be reached at shutdown costs that data, not a failed
// exit.
func flushTelemetry(tel *telemetry.Providers, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := tel.Shutdown(ctx); err != nil {
		log.WarnContext(ctx, "telemetry flush failed", "error", err)
	}
}

// loadStorage builds the S3 client from the SDK's default chain: the instance
// role on EC2, or a shared credentials file named by
// AWS_SHARED_CREDENTIALS_FILE elsewhere, so no secret is read from the
// environment. The region must be set explicitly: guessing one would sign
// links for the wrong endpoint.
func loadStorage(ctx context.Context, endpoint, bucket string) (*s3store.Store, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("s3: %w", err)
	}
	if awsCfg.Region == "" {
		return nil, errors.New("s3: AWS_REGION is not set")
	}
	return s3store.New(awsCfg, endpoint, bucket), nil
}

// githubProvider builds the GitHub provider. Its HTTP client has a timeout, so
// a hung GitHub request fails the sync instead of stalling every later one.
func githubProvider(g config.GitHub) (*github.Provider, error) {
	key, err := github.ParseAppKey(g.AppKey)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	auth := &github.AppAuth{
		BaseURL: g.APIURL, AppID: g.AppID, InstallationID: g.InstallationID,
		Key: key, HTTP: client, Now: time.Now,
	}
	return &github.Provider{
		Client:   &github.Client{BaseURL: g.APIURL, HTTP: client, Token: auth.Token},
		Org:      g.Org,
		Audience: g.Audience,
		JWKSURL:  g.JWKSURL,
		Now:      time.Now,
	}, nil
}
