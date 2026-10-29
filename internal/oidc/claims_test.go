package oidc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rurounijones/naraen/internal/datastore"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

const ghIssuer = "https://token.actions.githubusercontent.com"

var trusts = []datastore.WorkloadTrust{
	{Issuer: "https://other", Audience: "other-aud", RepoClaim: "project", MaxLevel: datastore.LevelRead},
	{Issuer: ghIssuer, Audience: "lfs.example.com", RepoClaim: "repository_id", MaxLevel: datastore.LevelRead},
}

func good() map[string]any {
	return map[string]any{
		"iss":           ghIssuer,
		"aud":           "lfs.example.com",
		"exp":           now.Add(time.Minute).Unix(),
		"nbf":           now.Add(-time.Minute).Unix(),
		"repository_id": "123",
		"project":       "not-this-one",
	}
}

func encode(t *testing.T, c map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheck(t *testing.T) {
	repo, max, err := Check(encode(t, good()), trusts, now)
	if err != nil || repo != "123" || max != datastore.LevelRead {
		t.Fatalf("Check = %q, %v, %v", repo, max, err)
	}
	// The repo claim is read from the entry that matched.
	c := good()
	c["iss"], c["aud"] = "https://other", []string{"other-aud"}
	repo, _, err = Check(encode(t, c), trusts, now)
	if err != nil || repo != "not-this-one" {
		t.Fatalf("other trust: %q, %v", repo, err)
	}
	// nbf is optional.
	c = good()
	delete(c, "nbf")
	if _, _, err := Check(encode(t, c), trusts, now); err != nil {
		t.Fatalf("without nbf: %v", err)
	}
}

func TestCheckCapsLevelAtRead(t *testing.T) {
	wide := []datastore.WorkloadTrust{{Issuer: ghIssuer, Audience: "lfs.example.com", RepoClaim: "repository_id", MaxLevel: datastore.LevelAdmin}}
	if _, max, err := Check(encode(t, good()), wide, now); err != nil || max != datastore.LevelRead {
		t.Fatalf("max = %v, %v; want read", max, err)
	}
}

func TestCheckRejects(t *testing.T) {
	tests := map[string]func(map[string]any){
		"wrong issuer":        func(c map[string]any) { c["iss"] = "https://evil" },
		"empty issuer":        func(c map[string]any) { c["iss"] = "" },
		"issuer not a string": func(c map[string]any) { c["iss"] = 1 },
		"no issuer":           func(c map[string]any) { delete(c, "iss") },
		"wrong audience":      func(c map[string]any) { c["aud"] = "sts.amazonaws.com" },
		"no audience":         func(c map[string]any) { delete(c, "aud") },
		"empty audience list": func(c map[string]any) { c["aud"] = []string{} },
		"two audiences":       func(c map[string]any) { c["aud"] = []string{"lfs.example.com", "sts.amazonaws.com"} },
		"audience not string": func(c map[string]any) { c["aud"] = 5 },
		"audience of other":   func(c map[string]any) { c["aud"] = "other-aud" },
		"expired":             func(c map[string]any) { c["exp"] = now.Unix() },
		"long expired":        func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() },
		"no expiry":           func(c map[string]any) { delete(c, "exp") },
		"expiry not a number": func(c map[string]any) { c["exp"] = "tomorrow" },
		"not yet valid":       func(c map[string]any) { c["nbf"] = now.Add(time.Second).Unix() },
		"nbf not a number":    func(c map[string]any) { c["nbf"] = "now" },
		"missing repo":        func(c map[string]any) { delete(c, "repository_id") },
		"empty repo":          func(c map[string]any) { c["repository_id"] = "" },
		"repo not a string":   func(c map[string]any) { c["repository_id"] = 123 },
		"repo in other claim": func(c map[string]any) { delete(c, "repository_id"); c["repository"] = "123" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := good()
			mutate(c)
			if _, _, err := Check(encode(t, c), trusts, now); !errors.Is(err, ErrRejected) {
				t.Fatalf("err = %v, want ErrRejected", err)
			}
		})
	}
	for name, payload := range map[string]string{
		"not json":  "nope",
		"array":     "[]",
		"oversized": `{"iss":"` + strings.Repeat("a", maxPayload) + `"}`,
	} {
		if _, _, err := Check([]byte(payload), trusts, now); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := Check(encode(t, good()), nil, now); !errors.Is(err, ErrRejected) {
		t.Errorf("no trust entries: %v", err)
	}
	blank := []datastore.WorkloadTrust{{RepoClaim: "repository_id"}}
	c := good()
	c["iss"], c["aud"] = "", ""
	if _, _, err := Check(encode(t, c), blank, now); !errors.Is(err, ErrRejected) {
		t.Errorf("blank trust entry matched blank claims: %v", err)
	}
	onlyAud := []datastore.WorkloadTrust{{Audience: "", Issuer: ghIssuer, RepoClaim: "repository_id"}}
	c = good()
	c["aud"] = ""
	if _, _, err := Check(encode(t, c), onlyAud, now); !errors.Is(err, ErrRejected) {
		t.Errorf("trust with empty audience matched: %v", err)
	}
}

func TestCheckAcceptsPayloadAtLimit(t *testing.T) {
	c := good()
	b := encode(t, c)
	c["pad"] = strings.Repeat("a", maxPayload-len(b)-len(`,"pad":""`))
	b = encode(t, c)
	if len(b) != maxPayload {
		t.Fatalf("payload is %d bytes", len(b))
	}
	if _, _, err := Check(b, trusts, now); err != nil {
		t.Fatalf("payload of exactly maxPayload: %v", err)
	}
}

func FuzzCheck(f *testing.F) {
	b, _ := json.Marshal(good())
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"aud":["a","b"]}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		repo, max, err := Check(payload, trusts, now)
		if err != nil {
			return
		}
		if repo == "" || max > datastore.LevelRead {
			t.Fatalf("accepted %q at %v", repo, max)
		}
	})
}
