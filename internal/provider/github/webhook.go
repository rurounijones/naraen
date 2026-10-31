package github

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/telemetry"
	"github.com/rurounijones/naraen/internal/webhook"
)

// maxDelivery bounds a webhook body. The events handled here are a few
// kilobytes; GitHub's own cap is far larger than anything they need.
const maxDelivery = 1 << 20

// ErrPayload is returned for a delivery whose body does not parse.
var ErrPayload = errors.New("github: malformed webhook payload")

type delivery struct {
	Action     string `json:"action"`
	Membership struct {
		User user `json:"user"`
	} `json:"membership"`
	Member     user `json:"member"`
	Repository struct {
		ID int64 `json:"id"`
	} `json:"repository"`
	Key struct {
		Key string `json:"key"`
	} `json:"key"`
}

// Narrowing maps one webhook delivery to the access it removes. Only
// removals are acted on, so a forged or replayed delivery that got past the
// signature check could at worst deny access until the next full sync:
//
//   - organization member_removed deactivates the person;
//   - member removed (a repository collaborator) drops that person's grant
//     on the repository;
//   - deploy_key deleted revokes the key, by the fingerprint of the public
//     key in the payload.
//
// Everything else, including team changes whose effect on effective
// permissions only a full sync can work out, narrows nothing.
func Narrowing(event string, body []byte) (datastore.Narrowing, error) {
	var d delivery
	if err := json.Unmarshal(body, &d); err != nil {
		return datastore.Narrowing{}, ErrPayload
	}
	// Separate ifs rather than a tagless switch, so mutation testing can
	// reach the event and action checks.
	if event == "organization" && d.Action == "member_removed" {
		if d.Membership.User.ID == 0 {
			return datastore.Narrowing{}, ErrPayload
		}
		return datastore.Narrowing{DeactivateIdentities: []string{PersonID(d.Membership.User.ID)}}, nil
	}
	if event == "member" && d.Action == "removed" {
		if d.Member.ID == 0 || d.Repository.ID == 0 {
			return datastore.Narrowing{}, ErrPayload
		}
		return datastore.Narrowing{DropGrants: []datastore.GrantRef{{
			IdentityID: PersonID(d.Member.ID), RepoID: strconv.FormatInt(d.Repository.ID, 10),
		}}}, nil
	}
	if event == "deploy_key" && d.Action == "deleted" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.Key.Key))
		if err != nil {
			return datastore.Narrowing{}, ErrPayload
		}
		return datastore.Narrowing{RevokeKeys: []string{ssh.FingerprintSHA256(pub)}}, nil
	}
	return datastore.Narrowing{}, nil
}

// empty reports whether n removes nothing.
func empty(n datastore.Narrowing) bool {
	return len(n.DeactivateIdentities) == 0 && len(n.DropGrants) == 0 && len(n.RevokeKeys) == 0
}

// Narrower is the part of the datastore a webhook writes to.
type Narrower interface{ Narrow(datastore.Narrowing) }

// WebhookHandler serves POST /webhooks/github. Deliveries must carry a valid
// X-Hub-Signature-256 for Secret; their removals are applied to Store at
// once, ahead of the next full sync.
type WebhookHandler struct {
	Secret []byte
	Store  Narrower
	Log    *slog.Logger
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	event, deliveryID := r.Header.Get("X-GitHub-Event"), r.Header.Get("X-GitHub-Delivery")
	log := h.Log.With("remote", r.RemoteAddr, "event", event, "delivery", deliveryID)
	telemetry.Annotate(ctx, attribute.String(telemetry.AttrEvent, event), attribute.String(telemetry.AttrDelivery, deliveryID))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDelivery))
	if err != nil {
		log.InfoContext(ctx, "webhook refused", "reason", "too_large")
		telemetry.Annotate(ctx, attribute.String(telemetry.AttrReason, "too_large"))
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := webhook.Verify(h.Secret, body, r.Header.Get("X-Hub-Signature-256")); err != nil {
		log.InfoContext(ctx, "webhook refused", "reason", "bad_signature")
		telemetry.Annotate(ctx, attribute.String(telemetry.AttrReason, "bad_signature"))
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	n, err := Narrowing(event, body)
	if err != nil {
		log.WarnContext(ctx, "webhook refused", "reason", "malformed")
		telemetry.Annotate(ctx, attribute.String(telemetry.AttrReason, "malformed"))
		http.Error(w, "malformed payload", http.StatusBadRequest)
		return
	}
	if !empty(n) {
		h.Store.Narrow(n)
		log.InfoContext(ctx, "webhook applied", "deactivated", n.DeactivateIdentities,
			"revoked_keys", n.RevokeKeys, "dropped_grants", len(n.DropGrants))
	} else {
		log.DebugContext(ctx, "webhook ignored")
	}
	w.WriteHeader(http.StatusAccepted)
}
