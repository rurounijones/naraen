// Package sshd is the SSH front door: it authenticates keys against the
// datastore and parses the git-lfs commands clients send.
package sshd

import (
	"errors"
	"strings"

	"github.com/rurounijones/naraen/internal/lfs"
	"github.com/rurounijones/naraen/internal/pathnorm"
)

// Command names a git-lfs client may execute over SSH.
const (
	CmdAuthenticate = "git-lfs-authenticate"
	CmdTransfer     = "git-lfs-transfer"
)

// maxCommandLength bounds the untrusted exec payload: the longest valid command
// is "git-lfs-authenticate " (21) + a path of pathnorm.MaxLength (200) + " download" (9).
const maxCommandLength = 230

// ErrBadCommand is returned for any command that is not exactly understood.
var ErrBadCommand = errors.New("sshd: bad command")

// Command is a parsed git-lfs SSH command.
type Command struct {
	Name string
	Repo string // normalized "owner/repo"
	Op   lfs.Operation
}

// ParseCommand parses "git-lfs-authenticate <path> <operation>" and
// "git-lfs-transfer <path> <operation>". Fields must be separated by single
// spaces; nothing else is tolerated.
func ParseCommand(s string) (Command, error) {
	if s == "" || len(s) > maxCommandLength {
		return Command{}, ErrBadCommand
	}
	parts := strings.Split(s, " ")
	if len(parts) != 3 {
		return Command{}, ErrBadCommand
	}
	if parts[0] != CmdAuthenticate && parts[0] != CmdTransfer {
		return Command{}, ErrBadCommand
	}
	repo, err := pathnorm.Normalize(parts[1])
	if err != nil {
		return Command{}, ErrBadCommand
	}
	op, err := lfs.ParseOperation(parts[2])
	if err != nil {
		return Command{}, ErrBadCommand
	}
	return Command{Name: parts[0], Repo: repo, Op: op}, nil
}
