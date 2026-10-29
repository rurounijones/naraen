// Package transferfeed will read completed S3 transfers (CloudTrail data events
// via EventBridge and SQS) and match each to the link that authorized it.
package transferfeed

import (
	"context"
	"time"
)

// Event is one completed object transfer.
type Event struct {
	Bucket   string
	Key      string
	SourceIP string
	Bytes    int64
	At       time.Time
	Upload   bool
}

// Feed yields transfer events until ctx is cancelled.
type Feed interface {
	Next(ctx context.Context) (Event, error)
}
