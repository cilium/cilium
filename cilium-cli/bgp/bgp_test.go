// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/require"
)

func Test_isLegacyCiliumVersion(t *testing.T) {
	testCases := []struct {
		Version        semver.Version
		expectedOutput bool
	}{
		{
			Version:        semver.MustParse("1.19.0"),
			expectedOutput: true,
		},
		{
			Version:        semver.MustParse("1.20.0-dev"),
			expectedOutput: false,
		},
		{
			Version:        semver.MustParse("1.20.0-pre.2"),
			expectedOutput: true,
		},
		{
			Version:        semver.MustParse("1.20.0-pre.4"),
			expectedOutput: false,
		},
		{
			Version:        semver.MustParse("1.20.0"),
			expectedOutput: false,
		},
	}

	for _, tt := range testCases {
		require.Equal(t, tt.expectedOutput, isLegacyCiliumVersion(tt.Version))
	}
}
