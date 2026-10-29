package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sign(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestVerify(t *testing.T) {
	const secret, body = "s3cret", `{"action":"removed"}`
	good := sign(secret, body)
	tests := []struct {
		name         string
		secret, body string
		header       string
		wantOK       bool
	}{
		{"valid", secret, body, good, true},
		{"wrong secret", "other", body, good, false},
		{"tampered body", secret, body + " ", good, false},
		{"empty secret", "", body, sign("", body), false},
		{"missing header", secret, body, "", false},
		{"missing prefix", secret, body, good[len("sha256="):], false},
		{"sha1 prefix", secret, body, "sha1=" + good[len("sha256="):], false},
		{"not hex", secret, body, "sha256=zz", false},
		{"truncated", secret, body, good[:len(good)-2], false},
		{"empty digest", secret, body, "sha256=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify([]byte(tt.secret), []byte(tt.body), tt.header)
			if (err == nil) != tt.wantOK {
				t.Fatalf("err = %v, wantOK %v", err, tt.wantOK)
			}
		})
	}
}

func FuzzVerify(f *testing.F) {
	f.Add("sha256=00", `{}`)
	f.Fuzz(func(t *testing.T, header, body string) {
		if err := Verify([]byte("fixed-secret"), []byte(body), header); err == nil && !strings.EqualFold(header, sign("fixed-secret", body)) {
			t.Fatalf("accepted non-canonical header %q", header)
		}
	})
}
