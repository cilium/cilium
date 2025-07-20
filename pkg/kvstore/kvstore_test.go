// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestGetLockPath(t *testing.T) {
	testutils.IntegrationTest(t)

	const path = "foo/path"
	require.Equal(t, path+".lock", getLockPath(path))
}

func TestValidateScopesFromKey(t *testing.T) {
	mockData := map[string]string{
		"cilium/state/identities/v1/id": "identities/v1",
		"cilium/state/identities/v1/value/Y29udGFpbmVyOmlkPWFwcDE7Y29udGFpbmVyOmlkLnNlcnZpY2UxPTs=": "identities/v1",
		"cilium/state/ip/v1/default/10.15.189.183":                                                  "ip/v1",
		"cilium/state/ip/v1/default/f00d::a0f:0:0:6f2e":                                             "ip/v1",
		"cilium/state/nodes/v1/default/runtime":                                                     "nodes/v1",
		"cilium/state/nodes/v1":                                                                     "nodes/v1",
	}

	for key, val := range mockData {
		require.Equal(t, val, GetScopeFromKey(key))
	}
}

func TestStateToCachePrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "a prefix starting with cilium/state",
			input:    "cilium/state/foo/bar",
			expected: "cilium/cache/foo/bar",
		},
		{
			name:     "a prefix not starting with cilium/state",
			input:    "cilium/foo/bar",
			expected: "cilium/foo/bar",
		},
		{
			name:     "a prefix containing but not starting with cilium/state",
			input:    "cilium/foo/bar/cilium/state/qux",
			expected: "cilium/foo/bar/cilium/state/qux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, StateToCachePrefix(tt.input))
		})
	}
}
