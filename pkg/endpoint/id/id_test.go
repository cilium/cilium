// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package id

import (
	. "gopkg.in/check.v1"
)

func (s *AllocatorSuite) TestSplitID(c *C) {
	type test struct {
		input      string
		wantPrefix PrefixType
		wantID     string
	}

	tests := []test{
		{DockerEndpointPrefix + ":foo", DockerEndpointPrefix, "foo"},
		{DockerEndpointPrefix + ":foo:foo", DockerEndpointPrefix, "foo:foo"},
		{"unknown:unknown", "unknown", "unknown"},
		{"unknown", CiliumLocalIdPrefix, "unknown"},
	}

	for _, t := range tests {
		prefix, id := SplitID(t.input)
		c.Assert(prefix, Equals, t.wantPrefix)
		c.Assert(id, Equals, t.wantID)
	}
}

func (s *AllocatorSuite) TestValidateID(c *C) {
	type test struct {
		input      string
		wantPrefix PrefixType
		wantID     string
		expectFail bool
	}

	tests := []test{
		{DockerEndpointPrefix + ":foo", DockerEndpointPrefix, "foo", false},
		{DockerEndpointPrefix + ":foo:foo", DockerEndpointPrefix, "foo:foo", false},
		{"unknown:unknown", "", "", true},
		{"unknown", CiliumLocalIdPrefix, "unknown", false},
	}

	for _, t := range tests {
		prefix, id, err := ValidateID(t.input)
		c.Assert(prefix, Equals, t.wantPrefix)
		c.Assert(id, Equals, t.wantID)
		if t.expectFail {
			c.Assert(err, Not(IsNil))
		} else {
			c.Assert(err, IsNil)
		}
	}
}
