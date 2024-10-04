// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioncheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMustCompile(t *testing.T) {
	tests := []struct {
		version    string
		constraint string
		want       bool
	}{
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.17.0",
			want:       false,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.16.3-beta.0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.16.3-beta.0",
			constraint: ">=1.11.0",
			want:       true,
		},
		{
			version:    "1.17.0",
			constraint: ">=1.17.0",
			want:       true,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.7",
			want:       true,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.6",
			want:       true,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.14.8",
			want:       false,
		},
		{
			version:    "1.14.7-eks-e9b1d0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.16.3-beta.0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.16.0-rc.2",
			constraint: ">=1.16.0",
			want:       false,
		},
		{
			version:    "1.17.0-alpha.2",
			constraint: ">=1.17.0-alpha.1",
			want:       true,
		},
		{
			version:    "1.14.0-snapshot.0",
			constraint: ">=1.13.0",
			want:       true,
		},
		{
			version:    "1.14.0-snapshot.1",
			constraint: ">=1.14.0-snapshot.0",
			want:       true,
		},
		{
			version:    "1.14.0-snapshot.0",
			constraint: ">=1.14.0",
			want:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			ver, err := Version(tt.version)
			require.NoError(t, err, "version %s, constraint %s", tt.version, tt.constraint)

			constraint, err := Compile(tt.constraint)
			require.NoError(t, err, "version %s, constraint %s", tt.version, tt.constraint)
			require.Equal(t, tt.want, constraint(ver), "version %s, constraint %s", tt.version, tt.constraint)
		})
	}
}
