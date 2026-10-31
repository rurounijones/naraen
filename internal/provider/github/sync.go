package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
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
// GitHub App installed on it sees it. FullSync must not run concurrently with
// itself; provider.Run calls it from one goroutine.
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

	cache caches
}

// caches holds one pageCache per listing a sync reads.
type caches struct {
	repos         pageCache[[]repoRef]
	members       pageCache[[]datastore.Identity]
	keys          pageCache[[]datastore.Key]
	collaborators pageCache[[]datastore.Grant]
	deployKeys    pageCache[repoData]
}

func (c *caches) begin() {
	c.repos.begin()
	c.members.begin()
	c.keys.begin()
	c.collaborators.begin()
	c.deployKeys.begin()
}

func (c *caches) sweep() {
	c.repos.sweep()
	c.members.sweep()
	c.keys.sweep()
	c.collaborators.sweep()
	c.deployKeys.sweep()
}

type repoRef struct{ id, fullName string }

// repoData is what one repo adds to a snapshot beyond the repo itself.
type repoData struct {
	identities []datastore.Identity
	keys       []datastore.Key
	grants     []datastore.Grant
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
// Members' keys and repos are read a few at a time (syncConcurrency), and
// pages GitHub reports unchanged since the last sync are reused (pageCache).
// The results are put together in the order GitHub listed them, whatever
// order the requests finished in.
//
// Any failure fails the whole sync, so a partial view of the organisation is
// never published; the store also validates the result against the live
// snapshot before swapping it in.
func (p *Provider) FullSync(ctx context.Context) (*datastore.Snapshot, error) {
	p.cache.begin()
	var d datastore.Data
	d.Meta = datastore.Meta{Provider: p.Name(), SyncedAt: p.Now().UTC()}
	repoPages, err := fetch(ctx, p.Client, &p.cache.repos, "", "/installation/repositories?per_page=100", parseRepos)
	if err != nil {
		return nil, err
	}
	repos := slices.Concat(repoPages...)
	for _, repo := range repos {
		d.Repos = append(d.Repos, datastore.Repo{ID: repo.id, Path: strings.ToLower(repo.fullName)})
	}
	memberPages, err := fetch(ctx, p.Client, &p.cache.members, "", "/orgs/"+url.PathEscape(p.Org)+"/members?per_page=100", ParseMembers)
	if err != nil {
		return nil, err
	}
	members := slices.Concat(memberPages...)
	d.Identities = append(d.Identities, members...)

	keys := make([][]datastore.Key, len(members))
	err = each(ctx, len(members), func(ctx context.Context, i int) error {
		m := members[i]
		pages, err := fetch(ctx, p.Client, &p.cache.keys, m.ID, "/users/"+url.PathEscape(m.Name)+"/keys?per_page=100",
			func(r io.Reader) ([]datastore.Key, error) { return parseKeys(r, m.ID) })
		keys[i] = slices.Concat(pages...)
		return err
	})
	if err != nil {
		return nil, err
	}
	d.Keys = slices.Concat(keys...)

	perRepo := make([]repoData, len(repos))
	err = each(ctx, len(repos), func(ctx context.Context, i int) error {
		var err error
		perRepo[i], err = p.syncRepo(ctx, members, repos[i])
		return err
	})
	if err != nil {
		return nil, err
	}
	for _, r := range perRepo {
		d.Identities = append(d.Identities, r.identities...)
		d.Keys = append(d.Keys, r.keys...)
		d.Grants = append(d.Grants, r.grants...)
	}
	if p.Audience != "" {
		if err := p.addActions(ctx, &d); err != nil {
			return nil, err
		}
	}
	snap, err := datastore.NewSnapshot(d)
	if err != nil {
		return nil, err
	}
	// Only after a complete sync: a failed one may have stopped before
	// using pages that are still current.
	p.cache.sweep()
	return snap, nil
}

// parseRepos converts one page of GET /installation/repositories.
func parseRepos(r io.Reader) ([]repoRef, error) {
	var page struct {
		Repositories []struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if err := json.NewDecoder(r).Decode(&page); err != nil {
		return nil, err
	}
	out := make([]repoRef, 0, len(page.Repositories))
	for _, repo := range page.Repositories {
		if repo.ID == 0 || repo.FullName == "" {
			return nil, errors.New("repository missing id or name")
		}
		out = append(out, repoRef{strconv.FormatInt(repo.ID, 10), repo.FullName})
	}
	return out, nil
}

// syncRepo reads a repo's member grants and deploy keys.
func (p *Provider) syncRepo(ctx context.Context, members []datastore.Identity, repo repoRef) (repoData, error) {
	owner, name, _ := strings.Cut(repo.fullName, "/")
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	grantPages, err := fetch(ctx, p.Client, &p.cache.collaborators, repo.id, base+"/collaborators?affiliation=all&per_page=100",
		func(r io.Reader) ([]datastore.Grant, error) { return ParseCollaborators(repo.id, r) })
	if err != nil {
		return repoData{}, err
	}
	keyPages, err := fetch(ctx, p.Client, &p.cache.deployKeys, repo.id, base+"/keys?per_page=100",
		func(r io.Reader) (repoData, error) { return parseDeployKeys(r, repo.id) })
	if err != nil {
		return repoData{}, err
	}
	out := repoData{grants: MemberGrants(members, slices.Concat(grantPages...))}
	for _, k := range keyPages {
		out.identities = append(out.identities, k.identities...)
		out.keys = append(out.keys, k.keys...)
		out.grants = append(out.grants, k.grants...)
	}
	return out, nil
}

// parseDeployKeys converts one page of GET /repos/{owner}/{repo}/keys into an
// identity per key, with read or write on repoID.
func parseDeployKeys(r io.Reader, repoID string) (repoData, error) {
	var page []struct {
		ID       int64  `json:"id"`
		Key      string `json:"key"`
		Title    string `json:"title"`
		ReadOnly bool   `json:"read_only"`
	}
	if err := json.NewDecoder(r).Decode(&page); err != nil {
		return repoData{}, err
	}
	var out repoData
	for _, k := range page {
		if k.ID == 0 {
			return repoData{}, errors.New("deploy key missing id")
		}
		id := DeployKeyID(k.ID)
		key, err := sshKey(k.Key, id)
		if err != nil {
			return repoData{}, err
		}
		level := datastore.LevelWrite
		if k.ReadOnly {
			level = datastore.LevelRead
		}
		out.identities = append(out.identities, datastore.Identity{ID: id, Kind: datastore.KindDeployKey, Name: k.Title, Active: true})
		out.keys = append(out.keys, key)
		out.grants = append(out.grants, datastore.Grant{IdentityID: id, RepoID: repoID, Level: level})
	}
	return out, nil
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
