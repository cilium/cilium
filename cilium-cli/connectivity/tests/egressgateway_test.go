// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"net/netip"
	"testing"
)

func TestExtractClientIPFromResponse(t *testing.T) {
	tests := []struct {
		name    string
		res     string
		want    netip.Addr
		wantErr bool
	}{
		{
			name: "IPv4",
			res:  `{"client-ip":"192.0.2.1"}`,
			want: netip.MustParseAddr("192.0.2.1"),
		},
		{
			name: "IPv4-mapped IPv6",
			res:  `{"client-ip":"::ffff:192.0.2.1"}`,
			want: netip.MustParseAddr("192.0.2.1"),
		},
		{
			name:    "empty response",
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			res:     `{"client-ip":`,
			wantErr: true,
		},
		{
			name:    "missing client IP",
			res:     `{}`,
			wantErr: true,
		},
		{
			name:    "invalid client IP",
			res:     `{"client-ip":"not-an-ip"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractClientIPFromResponse(tt.res)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("extractClientIPFromResponse(%q) returned no error", tt.res)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractClientIPFromResponse(%q) failed: %s", tt.res, err)
			}
			if got != tt.want {
				t.Fatalf("extractClientIPFromResponse(%q) = %s, want %s", tt.res, got, tt.want)
			}
		})
	}
}
