// Package s3store implements storage.Presigner on Amazon S3, or on any
// S3-compatible service reached through an endpoint override.
package s3store

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/rurounijones/naraen/internal/oid"
	"github.com/rurounijones/naraen/internal/storage"
)

// RequestIDParam is the query parameter that carries the server's request ID
// in every pre-signed URL. S3 ignores query parameters that start with "x-"
// but records them in its server access logs.
const RequestIDParam = "x-lfs-req"

// Store pre-signs object URLs and inspects one bucket.
type Store struct {
	bucket  string
	client  *s3.Client
	presign *s3.PresignClient
	// now is replaceable in tests.
	now func() time.Time
}

var _ storage.Presigner = (*Store)(nil)

// New returns a Store on bucket using cfg's region and credentials. A non-empty
// endpoint replaces the AWS endpoint and switches to path-style addressing,
// which S3-compatible services such as SeaweedFS need.
func New(cfg aws.Config, endpoint, bucket string) *Store {
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		}
		// Checksums are added only where the operation requires one. A PUT
		// link carries the object's SHA-256 explicitly; anything the SDK
		// added on its own would be a header or trailer the client never
		// sends.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &Store{
		bucket:  bucket,
		client:  client,
		presign: s3.NewPresignClient(client, s3.WithPresignExpires(storage.LinkTTL)),
		now:     time.Now,
	}
}

// PresignGet returns a download link for id.
func (s *Store) PresignGet(ctx context.Context, repoID string, id oid.OID, requestID string) (storage.Link, error) {
	expires := s.now().Add(storage.LinkTTL)
	req, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(storage.ObjectKey(repoID, id)),
	}, withRequestID(requestID))
	if err != nil {
		return storage.Link{}, fmt.Errorf("s3store: presign get: %w", err)
	}
	return storage.Link{URL: req.URL, Headers: clientHeaders(req.SignedHeader), Expires: expires}, nil
}

// PresignPut returns an upload link for id that S3 honours only for exactly
// size bytes whose SHA-256 is id.
func (s *Store) PresignPut(ctx context.Context, repoID string, id oid.OID, size int64, requestID string) (storage.Link, error) {
	// A valid OID is 64 hex digits, so this cannot fail.
	sum, _ := hex.DecodeString(string(id))
	expires := s.now().Add(storage.LinkTTL)
	req, err := s.presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:         aws.String(s.bucket),
		Key:            aws.String(storage.ObjectKey(repoID, id)),
		ContentLength:  aws.Int64(size),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum)),
	}, withRequestID(requestID))
	if err != nil {
		return storage.Link{}, fmt.Errorf("s3store: presign put: %w", err)
	}
	return storage.Link{URL: req.URL, Headers: clientHeaders(req.SignedHeader), Expires: expires}, nil
}

// Stat reports whether repoID has id stored, and its size.
func (s *Store) Stat(ctx context.Context, repoID string, id oid.OID) (int64, bool, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(storage.ObjectKey(repoID, id)),
	})
	var missing *types.NotFound
	if errors.As(err, &missing) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("s3store: head: %w", err)
	}
	return aws.ToInt64(out.ContentLength), true, nil
}

// clientHeaders returns the signed headers the client must send itself. Host
// and Content-Length are left out: every HTTP client sets them from the URL
// and the body, and git-lfs sends exactly the object's size.
func clientHeaders(signed http.Header) map[string]string {
	h := map[string]string{}
	for name, values := range signed {
		if name == "Host" || name == "Content-Length" || len(values) == 0 {
			continue
		}
		h[name] = values[0]
	}
	return h
}

// withRequestID adds requestID to the URL's query before it is signed, so the
// parameter is covered by the signature and cannot be swapped by the client.
func withRequestID(requestID string) func(*s3.PresignOptions) {
	return func(o *s3.PresignOptions) {
		o.ClientOptions = append(o.ClientOptions, func(so *s3.Options) {
			so.APIOptions = append(so.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(requestIDStep(requestID), middleware.After)
			})
		})
	}
}

// requestIDStep is the build step that adds the request ID. The build steps
// run before the presigner signs the request.
func requestIDStep(requestID string) middleware.BuildMiddleware {
	return middleware.BuildMiddlewareFunc("NaraenRequestID",
		func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
			if err := addQuery(in.Request, RequestIDParam, requestID); err != nil {
				return middleware.BuildOutput{}, middleware.Metadata{}, err
			}
			return next.HandleBuild(ctx, in)
		})
}

// addQuery sets one query parameter on a smithy HTTP request.
func addQuery(req any, name, value string) error {
	r, ok := req.(*smithyhttp.Request)
	if !ok {
		return fmt.Errorf("s3store: unexpected request type %T", req)
	}
	q := r.URL.Query()
	q.Set(name, value)
	r.URL.RawQuery = q.Encode()
	return nil
}
