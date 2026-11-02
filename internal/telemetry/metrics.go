// Package telemetry names the OpenTelemetry instruments the server emits. File
// IDs, IP addresses and request IDs belong on traces and logs, never on metric
// labels, to keep cardinality bounded.
package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metric names.
const (
	MetricLinksIssued       = "lfs.links.issued"
	MetricBytesRequested    = "lfs.bytes.requested"
	MetricBytesTransferred  = "lfs.bytes.transferred"
	MetricObjectSize        = "lfs.object.size"
	MetricAuthFailures      = "lfs.auth.failures"
	MetricTokensIssued      = "lfs.tokens.issued" // #nosec G101 -- a metric name, not a credential
	MetricSSHConnsRejected  = "lfs.ssh.connections.rejected"
	MetricTransferFeedLag   = "lfs.transfer_feed.lag"
	MetricDatastoreAge      = "lfs.datastore.age"
	MetricSyncFailures      = "lfs.sync.failures"
	MetricSyncRateLimitWait = "lfs.sync.rate_limit_wait"

	MetricSnapshotSaveFailures = "lfs.snapshot.save_failures"
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
	linksIssued   metric.Int64Counter
	bytesReq      metric.Int64Counter
	objectSize    metric.Int64Histogram
	syncFailures  metric.Int64Counter
	syncWait      metric.Float64Counter
	saveFailures  metric.Int64Counter
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
	linksIssued, _ := m.Int64Counter(MetricLinksIssued,
		metric.WithUnit("{object}"),
		metric.WithDescription("Objects answered by the Batch API, by outcome: a link issued, or why not"))
	bytesReq, _ := m.Int64Counter(MetricBytesRequested,
		metric.WithUnit("By"),
		metric.WithDescription("Bytes covered by the links issued, the earliest signal of a transfer"))
	objectSize, _ := m.Int64Histogram(MetricObjectSize,
		metric.WithUnit("By"),
		metric.WithDescription("Size of each object a link was issued for"))
	syncFailures, _ := m.Int64Counter(MetricSyncFailures,
		metric.WithUnit("{sync}"),
		metric.WithDescription("Provider full syncs that failed or that the datastore rejected"))
	syncWait, _ := m.Float64Counter(MetricSyncRateLimitWait,
		metric.WithUnit("s"),
		metric.WithDescription("Seconds the provider held its requests back for the source's rate limit"))
	saveFailures, _ := m.Int64Counter(MetricSnapshotSaveFailures,
		metric.WithUnit("{save}"),
		metric.WithDescription("Saves of the datastore snapshot to the bucket that failed"))
	return &Recorder{
		authFailures: authFailures, tokensIssued: tokensIssued, connsRejected: connsRejected,
		linksIssued: linksIssued, bytesReq: bytesReq, objectSize: objectSize, syncFailures: syncFailures,
		syncWait: syncWait, saveFailures: saveFailures,
	}
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

// Link outcomes of lfs.links.issued: a link was issued, or why not.
const (
	OutcomeIssued   = "issued"   // a link was issued
	OutcomePresent  = "present"  // upload skipped: the object is already stored
	OutcomeMissing  = "missing"  // download refused: the object is not stored
	OutcomeMismatch = "mismatch" // download refused: the stored size differs
	OutcomeError    = "error"    // storage failed
)

// LinkOutcome counts one object answered by the Batch API. outcome is one of
// the Outcome constants.
func (r *Recorder) LinkOutcome(ctx context.Context, op, repoID, user, outcome string) {
	r.linksIssued.Add(ctx, 1, metric.WithAttributes(
		attribute.String(LabelOperation, op),
		attribute.String(LabelRepo, repoID),
		attribute.String(LabelUser, user),
		attribute.String(LabelOutcome, outcome)))
}

// BytesRequested counts the bytes one Batch request was given links for.
func (r *Recorder) BytesRequested(ctx context.Context, op, repoID, user string, n int64) {
	r.bytesReq.Add(ctx, n, metric.WithAttributes(
		attribute.String(LabelOperation, op),
		attribute.String(LabelRepo, repoID),
		attribute.String(LabelUser, user)))
}

// ObjectSize records the size of one object a link was issued for. The user
// is left off: sizes are for capacity, not for watching people.
func (r *Recorder) ObjectSize(ctx context.Context, op, repoID string, size int64) {
	r.objectSize.Record(ctx, size, metric.WithAttributes(
		attribute.String(LabelOperation, op),
		attribute.String(LabelRepo, repoID)))
}

// Reasons of lfs.sync.failures.
const (
	SyncFailed      = "failed"       // the source could not be read
	SyncRateLimited = "rate_limited" // the source refused for its rate limit
	SyncRejected    = "rejected"     // the store refused the snapshot
)

// SyncFailure counts one provider full sync that did not reach the datastore.
// reason is one of the Sync constants.
func (r *Recorder) SyncFailure(ctx context.Context, reason string) {
	r.syncFailures.Add(ctx, 1, metric.WithAttributes(attribute.String(LabelReason, reason)))
}

// SnapshotSaveFailure counts one failed save of the datastore snapshot.
func (r *Recorder) SnapshotSaveFailure(ctx context.Context) {
	r.saveFailures.Add(ctx, 1)
}

// RateLimitWait counts d more of the provider's requests being held back for
// the source's rate limit. Requests refused together add only the time by
// which each extended the hold, so the total is time held, not a sum of
// overlapping waits.
func (r *Recorder) RateLimitWait(ctx context.Context, d time.Duration) {
	r.syncWait.Add(ctx, d.Seconds())
}

// ObserveDatastoreAge reports age, in seconds, as lfs.datastore.age at every
// collection: how old the snapshot serving requests is. The alert on it fires
// well before the staleness limit stops service. Nothing is reported until
// age has a value. As in NewRecorder, a registration error could only come
// from the constant name or unit, which TestObserveDatastoreAge exports.
func ObserveDatastoreAge(mp metric.MeterProvider, age func() (time.Duration, bool)) {
	_, _ = mp.Meter(scopeName).Float64ObservableGauge(MetricDatastoreAge,
		metric.WithUnit("s"),
		metric.WithDescription("Seconds since the live datastore snapshot's sync began reading its source"),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			if a, ok := age(); ok {
				o.Observe(a.Seconds())
			}
			return nil
		}))
}
