// Package github is the GitHub authorization provider. This file holds the pure
// mapping from GitHub API payloads to datastore entities; network access is
// added around it later.
//
// People are org members only. Their identities come from the members list,
// and collaborator listings contribute grants alone. Outside collaborators are
// therefore never given access: their SSH keys are not loaded, and their
// grants are dropped by MemberGrants.
package github

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/rurounijones/naraen/internal/datastore"
)

// maxPage bounds one API response body.
const maxPage = 32 << 20

type user struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

func (u user) valid() bool { return u.ID != 0 && u.Login != "" }

type collaborator struct {
	user
	Permissions struct {
		Admin    bool `json:"admin"`
		Maintain bool `json:"maintain"`
		Push     bool `json:"push"`
		Triage   bool `json:"triage"`
		Pull     bool `json:"pull"`
	} `json:"permissions"`
}

// level maps GitHub's effective permission flags to a datastore level. Triage
// grants read access to LFS content, not write.
func (c collaborator) level() datastore.Level {
	switch p := c.Permissions; {
	case p.Admin:
		return datastore.LevelAdmin
	case p.Maintain:
		return datastore.LevelMaintain
	case p.Push:
		return datastore.LevelWrite
	case p.Triage, p.Pull:
		return datastore.LevelRead
	default:
		return datastore.LevelNone
	}
}

// PersonID is the stable identity ID for a GitHub user.
func PersonID(githubUserID int64) string { return "gh-user-" + strconv.FormatInt(githubUserID, 10) }

// ParseMembers converts one page of GET /orgs/{org}/members into person
// identities.
func ParseMembers(r io.Reader) ([]datastore.Identity, error) {
	var raw []user
	if err := json.NewDecoder(io.LimitReader(r, maxPage)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("github: decode members: %w", err)
	}
	out := make([]datastore.Identity, 0, len(raw))
	for _, u := range raw {
		if !u.valid() {
			return nil, fmt.Errorf("github: member missing id or login")
		}
		out = append(out, datastore.Identity{ID: PersonID(u.ID), Kind: datastore.KindPerson, Name: u.Login, Active: true})
	}
	return out, nil
}

// ParseCollaborators converts one page of
// GET /repos/{owner}/{repo}/collaborators?affiliation=all into grants for
// repoID. Collaborators with no effective permission are dropped.
func ParseCollaborators(repoID string, r io.Reader) ([]datastore.Grant, error) {
	var raw []collaborator
	if err := json.NewDecoder(io.LimitReader(r, maxPage)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("github: decode collaborators: %w", err)
	}
	out := make([]datastore.Grant, 0, len(raw))
	for _, c := range raw {
		if !c.valid() {
			return nil, fmt.Errorf("github: collaborator missing id or login")
		}
		lvl := c.level()
		if lvl == datastore.LevelNone {
			continue
		}
		out = append(out, datastore.Grant{IdentityID: PersonID(c.ID), RepoID: repoID, Level: lvl})
	}
	return out, nil
}

// MemberGrants keeps the grants held by members. Collaborator listings include
// outside collaborators, who have no identity in the datastore; a grant for
// them would make the snapshot invalid, and would be meaningless anyway
// because their keys are never loaded.
func MemberGrants(members []datastore.Identity, grants []datastore.Grant) []datastore.Grant {
	known := make(map[string]bool, len(members))
	for _, m := range members {
		known[m.ID] = true
	}
	out := make([]datastore.Grant, 0, len(grants))
	for _, g := range grants {
		if known[g.IdentityID] {
			out = append(out, g)
		}
	}
	return out
}
