// Package lfs holds the small vocabulary shared by every layer of the server.
package lfs

import "fmt"

// Operation is a Git LFS transfer direction.
type Operation string

const (
	Download Operation = "download"
	Upload   Operation = "upload"
)

// ParseOperation accepts exactly "download" or "upload".
func ParseOperation(s string) (Operation, error) {
	switch Operation(s) {
	case Download:
		return Download, nil
	case Upload:
		return Upload, nil
	default:
		return "", fmt.Errorf("lfs: unknown operation %q", s)
	}
}
