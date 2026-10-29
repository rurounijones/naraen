package lfs

import "testing"

func TestParseOperation(t *testing.T) {
	tests := []struct {
		in      string
		want    Operation
		wantErr bool
	}{
		{"download", Download, false},
		{"upload", Upload, false},
		{"", "", true},
		{"Download", "", true},
		{"delete", "", true},
	}
	for _, tt := range tests {
		got, err := ParseOperation(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseOperation(%q) = %q, %v", tt.in, got, err)
		}
	}
}
