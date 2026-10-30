// Command naraen is the S3 LFS server: an SSH listener for authentication and an
// HTTPS listener for the Batch API.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/authz"
	"github.com/rurounijones/naraen/internal/config"
	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/httpapi"
	"github.com/rurounijones/naraen/internal/sshd"
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
	if cfg.SnapshotFile != "" {
		if err := loadSnapshot(store, cfg.SnapshotFile, cfg.Dev); err != nil {
			return err
		}
		if !cfg.Dev {
			log.WarnContext(ctx, "datastore loaded from a snapshot file: no provider keeps it in step with GitHub", "file", cfg.SnapshotFile)
		}
	}
	// Until a provider is wired in, the server stays not-ready and refuses all
	// requests unless a snapshot file was supplied.

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
	httpSrv := httpapi.NewServer(cfg.HTTPSAddr, httpapi.Handler(store), httpapi.TLSConfig(cert))

	sshLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.SSHAddr)
	if err != nil {
		return fmt.Errorf("ssh listen: %w", err)
	}
	authorizer := authz.New(store)
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
