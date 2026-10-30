// Package telemetry names the OpenTelemetry instruments the server emits. File
// IDs, IP addresses and request IDs belong on traces and logs, never on metric
// labels, to keep cardinality bounded.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metric names.
const (
	MetricLinksIssued      = "lfs.links.issued"
	MetricBytesRequested   = "lfs.bytes.requested"
	MetricBytesTransferred = "lfs.bytes.transferred"
	MetricObjectSize       = "lfs.object.size"
	MetricAuthFailures     = "lfs.auth.failures"
	MetricTokensIssued     = "lfs.tokens.issued" // #nosec G101 -- a metric name, not a credential
	MetricSSHConnsRejected = "lfs.ssh.connections.rejected"
	MetricTransferFeedLag  = "lfs.transfer_feed.lag"
)

// Label names allowed on metrics.
const (
	LabelOperation    = "operation"
	LabelRepo         = "repo"
	LabelUser         = "user"
	LabelOutcome      = "outcome"
	LabelReason       = "reason"
	LabelIdentityType = "identity_type"
)

// IdentityTypeUnknown labels failures where no identity could be resolved,
// such as an SSH key the datastore does not hold.
const IdentityTypeUnknown = "unknown"

// scopeName scopes every instrument and log record to this server.
const scopeName = "github.com/rurounijones/naraen"

// Recorder emits the server's audit metrics: every token issued and every
// refusal, so alerts on refused sign-ins and unusual issuance work from
// metrics in real time rather than from logs.
type Recorder struct {
	authFailures  metric.Int64Counter
	tokensIssued  metric.Int64Counter
	connsRejected metric.Int64Counter
}

// NewRecorder creates the instruments on mp.
func NewRecorder(mp metric.MeterProvider) *Recorder {
	m := mp.Meter(scopeName)
	// Instrument creation fails only for an invalid name or unit. Both are
	// constants that TestRecorder exports, and on failure the API still
	// returns a working no-op instrument, so the errors carry nothing to act on.
	authFailures, _ := m.Int64Counter(MetricAuthFailures,
		metric.WithUnit("{failure}"),
		metric.WithDescription("SSH sign-ins and requests refused, by reason and identity type"))
	tokensIssued, _ := m.Int64Counter(MetricTokensIssued,
		metric.WithUnit("{token}"),
		metric.WithDescription("Bearer tokens issued by git-lfs-authenticate"))
	connsRejected, _ := m.Int64Counter(MetricSSHConnsRejected,
		metric.WithUnit("{connection}"),
		metric.WithDescription("SSH connections closed before the handshake by a rate or concurrency limit"))
	return &Recorder{authFailures: authFailures, tokensIssued: tokensIssued, connsRejected: connsRejected}
}

// AuthFailure counts one refusal. reason must come from a closed set (such as
// authz.Reason), never from client input.
func (r *Recorder) AuthFailure(ctx context.Context, reason, identityType string) {
	r.authFailures.Add(ctx, 1, metric.WithAttributes(
		attribute.String(LabelReason, reason),
		attribute.String(LabelIdentityType, identityType)))
}

// TokenIssued counts one bearer token. repoID, not the path, labels it, so a
// rename does not split the series.
func (r *Recorder) TokenIssued(ctx context.Context, op, repoID, user string) {
	r.tokensIssued.Add(ctx, 1, metric.WithAttributes(
		attribute.String(LabelOperation, op),
		attribute.String(LabelRepo, repoID),
		attribute.String(LabelUser, user)))
}

// ConnectionRejected counts one SSH connection closed by a limit before the
// handshake. reason is "rate" or "concurrency".
func (r *Recorder) ConnectionRejected(ctx context.Context, reason string) {
	r.connsRejected.Add(ctx, 1, metric.WithAttributes(attribute.String(LabelReason, reason)))
}
