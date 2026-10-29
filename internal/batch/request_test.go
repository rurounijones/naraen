package batch

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/rurounijones/naraen/internal/lfs"
)

var goodOID = strings.Repeat("ab", 32)

func body(op string, objs ...string) string {
	return fmt.Sprintf(`{"operation":%q,"transfers":["basic"],"objects":[%s]}`, op, strings.Join(objs, ","))
}

func obj(oid string, size int64) string { return fmt.Sprintf(`{"oid":%q,"size":%d}`, oid, size) }

func nthOID(i int) string { return fmt.Sprintf("%064x", i) }

func TestParseRequest(t *testing.T) {
	r, err := ParseRequest(strings.NewReader(body("upload", obj(goodOID, 0), obj(strings.Repeat("0", 64), MaxObjectSize))))
	if err != nil {
		t.Fatal(err)
	}
	if r.Operation != lfs.Upload || len(r.Objects) != 2 || string(r.Objects[0].OID) != goodOID || r.Objects[1].Size != MaxObjectSize {
		t.Errorf("request = %+v", r)
	}
}

func TestParseRequestLimits(t *testing.T) {
	valid := body("download", obj(goodOID, 1))
	atCap := strings.Repeat(" ", MaxBodyBytes-len(valid)) + valid
	if len(atCap) != MaxBodyBytes {
		t.Fatalf("test body is %d bytes", len(atCap))
	}
	if _, err := ParseRequest(strings.NewReader(atCap)); err != nil {
		t.Errorf("body of exactly MaxBodyBytes: %v", err)
	}
	if _, err := ParseRequest(strings.NewReader(" " + atCap)); err == nil {
		t.Error("body one byte over MaxBodyBytes accepted")
	}
	if _, err := ParseRequest(strings.NewReader(valid + strings.Repeat(" ", MaxBodyBytes))); err == nil {
		t.Error("body padded far over MaxBodyBytes accepted")
	}
	if _, err := ParseRequest(iotest.ErrReader(errors.New("read failed"))); err == nil {
		t.Error("unreadable body accepted")
	}
	objs := make([]string, MaxObjects)
	for i := range objs {
		objs[i] = obj(nthOID(i), 1)
	}
	r, err := ParseRequest(strings.NewReader(body("download", objs...)))
	if err != nil || len(r.Objects) != MaxObjects {
		t.Errorf("exactly MaxObjects: %d objects, %v", len(r.Objects), err)
	}
}

func TestParseRequestRejects(t *testing.T) {
	many := make([]string, MaxObjects+1)
	for i := range many {
		many[i] = obj(nthOID(i), 1)
	}
	tests := map[string]string{
		"empty body":        ``,
		"not json":          `nope`,
		"array":             `[]`,
		"trailing data":     body("download", obj(goodOID, 1)) + `{}`,
		"missing operation": `{"objects":[` + obj(goodOID, 1) + `]}`,
		"bad operation":     body("delete", obj(goodOID, 1)),
		"no objects":        body("download"),
		"too many objects":  body("download", many...),
		"short oid":         body("download", obj(goodOID[:63], 1)),
		"uppercase oid":     body("download", obj(strings.ToUpper(goodOID), 1)),
		"path oid":          body("download", obj("../../"+goodOID[:58], 1)),
		"negative size":     body("download", obj(goodOID, -1)),
		"oversized object":  body("download", obj(goodOID, MaxObjectSize+1)),
		"size wrong type":   `{"operation":"download","objects":[{"oid":"` + goodOID + `","size":"1"}]}`,
		"second object bad": body("download", obj(goodOID, 1), obj("x", 1)),
		"body over the cap": `{"operation":"download","objects":[],"pad":"` + strings.Repeat("a", MaxBodyBytes) + `"}`,
		"no basic transfer": `{"operation":"download","transfers":["ssh"],"objects":[` + obj(goodOID, 1) + `]}`,
		"empty transfers":   `{"operation":"download","transfers":[],"objects":[` + obj(goodOID, 1) + `]}`,
		"sha1 hash_algo":    `{"operation":"download","hash_algo":"sha1","objects":[` + obj(goodOID, 1) + `]}`,
		"empty hash_algo":   `{"operation":"download","hash_algo":"","objects":[` + obj(goodOID, 1) + `]}`,
		"conflicting sizes": body("download", obj(goodOID, 1), obj(goodOID, 2)),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequest(strings.NewReader(in)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseRequestNegotiation(t *testing.T) {
	for name, in := range map[string]string{
		"no transfers or hash_algo": `{"operation":"download","objects":[` + obj(goodOID, 1) + `]}`,
		"null transfers":            `{"operation":"download","transfers":null,"objects":[` + obj(goodOID, 1) + `]}`,
		"basic among others":        `{"operation":"download","transfers":["lfs-standalone-file","basic"],"objects":[` + obj(goodOID, 1) + `]}`,
		"sha256 hash_algo":          `{"operation":"download","hash_algo":"sha256","objects":[` + obj(goodOID, 1) + `]}`,
	} {
		if _, err := ParseRequest(strings.NewReader(in)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseRequestMergesRepeats(t *testing.T) {
	r, err := ParseRequest(strings.NewReader(body("download", obj(goodOID, 3), obj(nthOID(1), 4), obj(goodOID, 3))))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Objects) != 2 || string(r.Objects[0].OID) != goodOID || string(r.Objects[1].OID) != nthOID(1) {
		t.Fatalf("objects = %+v", r.Objects)
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add(body("download", obj(goodOID, 5)))
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, in string) {
		r, err := ParseRequest(strings.NewReader(in))
		if err != nil {
			return
		}
		if len(r.Objects) == 0 || len(r.Objects) > MaxObjects {
			t.Fatalf("accepted %d objects", len(r.Objects))
		}
		seen := make(map[string]bool, len(r.Objects))
		for _, o := range r.Objects {
			if len(o.OID) != 64 || o.Size < 0 || o.Size > MaxObjectSize || seen[string(o.OID)] {
				t.Fatalf("accepted bad or repeated object %+v", o)
			}
			seen[string(o.OID)] = true
		}
	})
}
