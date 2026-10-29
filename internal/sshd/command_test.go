package sshd

import (
	"strings"
	"testing"

	"github.com/rurounijones/naraen/internal/lfs"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		in      string
		want    Command
		wantErr bool
	}{
		{"git-lfs-authenticate acme/assets download", Command{CmdAuthenticate, "acme/assets", lfs.Download}, false},
		{"git-lfs-authenticate /Acme/Assets.git upload", Command{CmdAuthenticate, "acme/assets", lfs.Upload}, false},
		{"git-lfs-transfer acme/assets upload", Command{CmdTransfer, "acme/assets", lfs.Upload}, false},
		{"", Command{}, true},
		{"ls", Command{}, true},
		{"git-lfs-authenticate", Command{}, true},
		{"git-lfs-authenticate acme/assets", Command{}, true},
		{"git-lfs-authenticate acme/assets download extra", Command{}, true},
		{"git-lfs-authenticate  acme/assets download", Command{}, true},
		{"git-lfs-authenticate acme/assets  download", Command{}, true},
		{"git-lfs-authenticate acme/assets delete", Command{}, true},
		{"git-lfs-authenticate ../assets download", Command{}, true},
		{"git-lfs-authenticate acme/assets download;id", Command{}, true},
		{"git-lfs-authenticate acme/assets\tdownload", Command{}, true},
		{"git-upload-pack acme/assets download", Command{}, true},
		{"GIT-LFS-AUTHENTICATE acme/assets download", Command{}, true},
		{"git-lfs-authenticate acme/assets download\n", Command{}, true},
		{strings.Repeat("a", maxCommandLength+1), Command{}, true},
		{
			"git-lfs-authenticate /" + strings.Repeat("a", 99) + "/" + strings.Repeat("b", 99) + " download",
			Command{CmdAuthenticate, strings.Repeat("a", 99) + "/" + strings.Repeat("b", 99), lfs.Download},
			false,
		}, // exactly maxCommandLength
	}
	for _, tt := range tests {
		got, err := ParseCommand(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseCommand(%q) = %+v, %v", tt.in, got, err)
		}
	}
}

func FuzzParseCommand(f *testing.F) {
	f.Add("git-lfs-authenticate acme/assets download")
	f.Add("git-lfs-transfer a/b upload")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCommand(s)
		if err != nil {
			return
		}
		if c.Repo == "" || strings.Count(c.Repo, "/") != 1 {
			t.Fatalf("ParseCommand(%q) produced repo %q", s, c.Repo)
		}
		if c.Op != lfs.Download && c.Op != lfs.Upload {
			t.Fatalf("ParseCommand(%q) produced op %q", s, c.Op)
		}
	})
}
