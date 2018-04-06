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

package api

import (
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

var _ = Suite(&PolicyAPITestSuite{})

func (s *PolicyAPITestSuite) TestSelectsAllEndpoints(c *C) {

	// Empty endpoint selector slice equates to a wildcard.
	selectorSlice := EndpointSelectorSlice{}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	// Slice that contains wildcard and other selectors still selects all endpoints.
	selectorSlice = EndpointSelectorSlice{WildcardEndpointSelector, NewESFromLabels(labels.ParseSelectLabel("bar"))}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, true)

	selectorSlice = EndpointSelectorSlice{NewESFromLabels(labels.ParseSelectLabel("bar")), NewESFromLabels(labels.ParseSelectLabel("foo"))}
	c.Assert(selectorSlice.SelectsAllEndpoints(), Equals, false)
}
