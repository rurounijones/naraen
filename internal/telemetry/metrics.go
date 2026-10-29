// Package telemetry names the OpenTelemetry instruments the server emits. File
// IDs, IP addresses and request IDs belong on traces and logs, never on metric
// labels, to keep cardinality bounded.
package telemetry

// Metric names.
const (
	MetricLinksIssued      = "lfs.links.issued"
	MetricBytesRequested   = "lfs.bytes.requested"
	MetricBytesTransferred = "lfs.bytes.transferred"
	MetricObjectSize       = "lfs.object.size"
	MetricAuthFailures     = "lfs.auth.failures"
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
