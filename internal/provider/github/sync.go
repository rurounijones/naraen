package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rurounijones/naraen/internal/datastore"
	"github.com/rurounijones/naraen/internal/oidc"
)

// GitHub Actions' OIDC issuer and its signing keys.
const (
	ActionsIssuer  = "https://token.actions.githubusercontent.com"
	ActionsJWKSURL = ActionsIssuer + "/.well-known/jwks"
)

// maxJWKS bounds the issuer's key document.
const maxJWKS = 1 << 20

// Provider builds datastore snapshots from one GitHub organisation, as the
// GitHub App installed on it sees it.
type Provider struct {
	Client *Client
	Org    string
	// Audience is the custom audience CI jobs request their OIDC tokens
	// for. Empty means no workload trust is registered and CI cannot
	// exchange tokens.
	Audience string
	// JWKSURL is where the Actions issuer's keys are fetched, without
	// authentication.
	JWKSURL string
	// Now is replaceable in tests.
	Now func() time.Time
}

// Name identifies the provider in snapshot metadata and logs.
func (p *Provider) Name() string { return "github" }

// DeployKeyID is the stable identity ID for a repository deploy key.
func DeployKeyID(keyID int64) string { return "gh-deploy-key-" + strconv.FormatInt(keyID, 10) }

// FullSync reads the organisation and builds a complete snapshot:
//
//   - repos: those the App is installed on, keyed by numeric repo ID;
//   - people: org members and their SSH authentication keys (never their
//     signing keys, which GitHub serves elsewhere);
//   - grants: each repo's collaborators with effective permissions,
//     outside collaborators dropped;
//   - deploy keys: one identity per key, with read or write on its repo;
//   - CI: with an audience configured, a trust for GitHub Actions' issuer
//     holding its current keys, and a workload identity with read on each
//     repo.
//
// Any failure fails the whole sync, so a partial view of the organisation is
// never published; the store also validates the result against the live
// snapshot before swapping it in.
func (p *Provider) FullSync(ctx context.Context) (*datastore.Snapshot, error) {
	var d datastore.Data
	d.Meta = datastore.Meta{Provider: p.Name(), SyncedAt: p.Now().UTC()}
	type repoRef struct{ id, fullName string }
	var repos []repoRef
	err := p.Client.pages(ctx, "/installation/repositories?per_page=100", func(r io.Reader) error {
		var page struct {
			Repositories []struct {
				ID       int64  `json:"id"`
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		if err := json.NewDecoder(r).Decode(&page); err != nil {
			return err
		}
		for _, repo := range page.Repositories {
			if repo.ID == 0 || repo.FullName == "" {
				return errors.New("repository missing id or name")
			}
			id := strconv.FormatInt(repo.ID, 10)
			repos = append(repos, repoRef{id, repo.FullName})
			d.Repos = append(d.Repos, datastore.Repo{ID: id, Path: strings.ToLower(repo.FullName)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := p.Client.pages(ctx, "/orgs/"+url.PathEscape(p.Org)+"/members?per_page=100", func(r io.Reader) error {
		members, err := ParseMembers(r)
		d.Identities = append(d.Identities, members...)
		return err
	}); err != nil {
		return nil, err
	}
	for _, m := range d.Identities {
		if err := p.Client.pages(ctx, "/users/"+url.PathEscape(m.Name)+"/keys?per_page=100", func(r io.Reader) error {
			keys, err := parseKeys(r, m.ID)
			d.Keys = append(d.Keys, keys...)
			return err
		}); err != nil {
			return nil, err
		}
	}
	members := append([]datastore.Identity(nil), d.Identities...)
	for _, repo := range repos {
		if err := p.syncRepo(ctx, &d, members, repo.id, repo.fullName); err != nil {
			return nil, err
		}
	}
	if p.Audience != "" {
		if err := p.addActions(ctx, &d); err != nil {
			return nil, err
		}
	}
	return datastore.NewSnapshot(d)
}

// syncRepo adds a repo's member grants and deploy keys.
func (p *Provider) syncRepo(ctx context.Context, d *datastore.Data, members []datastore.Identity, repoID, fullName string) error {
	owner, name, _ := strings.Cut(fullName, "/")
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	if err := p.Client.pages(ctx, base+"/collaborators?affiliation=all&per_page=100", func(r io.Reader) error {
		grants, err := ParseCollaborators(repoID, r)
		d.Grants = append(d.Grants, MemberGrants(members, grants)...)
		return err
	}); err != nil {
		return err
	}
	return p.Client.pages(ctx, base+"/keys?per_page=100", func(r io.Reader) error {
		var page []struct {
			ID       int64  `json:"id"`
			Key      string `json:"key"`
			Title    string `json:"title"`
			ReadOnly bool   `json:"read_only"`
		}
		if err := json.NewDecoder(r).Decode(&page); err != nil {
			return err
		}
		for _, k := range page {
			if k.ID == 0 {
				return errors.New("deploy key missing id")
			}
			id := DeployKeyID(k.ID)
			key, err := sshKey(k.Key, id)
			if err != nil {
				return err
			}
			level := datastore.LevelWrite
			if k.ReadOnly {
				level = datastore.LevelRead
			}
			d.Identities = append(d.Identities, datastore.Identity{ID: id, Kind: datastore.KindDeployKey, Name: k.Title, Active: true})
			d.Keys = append(d.Keys, key)
			d.Grants = append(d.Grants, datastore.Grant{IdentityID: id, RepoID: repoID, Level: level})
		}
		return nil
	})
}

// addActions registers GitHub Actions as a workload issuer with its current
// keys, and gives each repo's workload identity read access to that repo.
// The keys are fetched here, by the provider, so verifying a CI token on the
// request path never needs the network.
func (p *Provider) addActions(ctx context.Context, d *datastore.Data) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("github: jwks request: %w", err)
	}
	resp, err := p.Client.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("github: jwks: %w", err)
	}
	defer resp.Body.Close()
	jwks, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS+1))
	if err != nil || len(jwks) > maxJWKS || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github: jwks: status %d", resp.StatusCode)
	}
	d.Trusts = append(d.Trusts, datastore.WorkloadTrust{
		Issuer: ActionsIssuer, Audience: p.Audience, JWKS: string(jwks),
		RepoClaim: "repository_id", MaxLevel: datastore.LevelRead,
	})
	for _, repo := range d.Repos {
		id := oidc.WorkloadPrefix + repo.ID
		d.Identities = append(d.Identities, datastore.Identity{ID: id, Kind: datastore.KindWorkload, Name: "actions:" + repo.Path, Active: true})
		d.Grants = append(d.Grants, datastore.Grant{IdentityID: id, RepoID: repo.ID, Level: datastore.LevelRead})
	}
	return nil
}

// parseKeys converts one page of GET /users/{login}/keys into keys held by
// identityID.
func parseKeys(r io.Reader, identityID string) ([]datastore.Key, error) {
	var page []struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r).Decode(&page); err != nil {
		return nil, err
	}
	out := make([]datastore.Key, 0, len(page))
	for _, k := range page {
		key, err := sshKey(k.Key, identityID)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

func sshKey(authorized, identityID string) (datastore.Key, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return datastore.Key{}, fmt.Errorf("ssh key for %s: %w", identityID, err)
	}
	return datastore.Key{Fingerprint: ssh.FingerprintSHA256(pub), Type: pub.Type(), IdentityID: identityID}, nil
}
