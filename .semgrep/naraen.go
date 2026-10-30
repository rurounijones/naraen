// Test cases for naraen.yml, run by `semgrep --test` in task sec.
// Each "ruleid" line must match and each "ok" line must not. The directory
// starts with a dot, so the Go tools never build this file, and task sec
// excludes it from the scan itself.
package rules

import (
	"bytes"
	"context"
	"crypto/hmac"
	"log/slog"
)

type config struct{ PublicURL string }

type link struct{ URL string }

func logging(ctx context.Context, log *slog.Logger, tok, presigned string, l link, cfg config, id, repoID string, err error) {
	// ok: naraen-log-presigned-url
	log.InfoContext(ctx, "token issued", "token_id", id, "repo_id", repoID)
	// ok: naraen-log-presigned-url
	slog.Info("listening", "public_origin", cfg.PublicURL)
	// ok: naraen-log-presigned-url
	log.With("identity", id, "fingerprint", "SHA256:x").Info("ssh authenticated")
	// A message that names what failed is not a key, even before a key/value pair.
	// ok: naraen-log-presigned-url
	log.ErrorContext(ctx, "presign failed", "request_id", id, "error", err)
	// ok: naraen-log-presigned-url
	log.Info("signed url refused", "repo_id", repoID)

	// ruleid: naraen-log-presigned-url
	log.InfoContext(ctx, "issued", "token", tok)
	// ruleid: naraen-log-presigned-url
	log.Info("issued", "value", tok)
	// ruleid: naraen-log-presigned-url
	slog.Warn("link", "u", l.URL)
	// ruleid: naraen-log-presigned-url
	log.Debug("link", "presigned_url", presigned)
	// ruleid: naraen-log-presigned-url
	log.ErrorContext(ctx, "request", "authorization", id)
	// ruleid: naraen-log-presigned-url
	log.With("href", id).Info("issued")
	// ruleid: naraen-log-presigned-url
	log.LogAttrs(ctx, slog.LevelInfo, "issued", slog.String("token", tok))
}

func compare(token, other []byte, mac, sig string) bool {
	// ruleid: naraen-nonconstant-secret-compare
	if bytes.Equal(token, other) {
		return true
	}
	// ruleid: naraen-nonconstant-secret-compare
	if mac == sig {
		return true
	}
	// ok: naraen-nonconstant-secret-compare
	if len(token) == 32 {
		return true
	}
	// ok: naraen-nonconstant-secret-compare
	return hmac.Equal(token, other)
}
