// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/testutils"
)

func Test(t *testing.T) {
	TestingT(t)
}

// independentSuite tests are tests which can run without creating a backend
type independentSuite struct{}

var _ = Suite(&independentSuite{})

func (s *independentSuite) SetUpSuite(c *C) {
	testutils.IntegrationTest(c)
}

func (s *independentSuite) TestGetLockPath(c *C) {
	const path = "foo/path"
	c.Assert(getLockPath(path), Equals, path+".lock")
}

func (s *independentSuite) TestValidateScopesFromKey(c *C) {
	mockData := map[string]string{
		"cilium/state/identities/v1/id": "identities/v1",
		"cilium/state/identities/v1/value/Y29udGFpbmVyOmlkPWFwcDE7Y29udGFpbmVyOmlkLnNlcnZpY2UxPTs=": "identities/v1",
		"cilium/state/ip/v1/default/10.15.189.183":                                                  "ip/v1",
		"cilium/state/ip/v1/default/f00d::a0f:0:0:6f2e":                                             "ip/v1",
		"cilium/state/nodes/v1/default/runtime":                                                     "nodes/v1",
		"cilium/state/nodes/v1":                                                                     "nodes/v1",
	}

	for key, val := range mockData {
		c.Assert(GetScopeFromKey(key), Equals, val)
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
