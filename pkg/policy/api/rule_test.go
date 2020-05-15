// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package api

import (
	"encoding/json"

	. "gopkg.in/check.v1"
)

func checkMarshalUnmarshal(c *C, r *Rule) {
	jsonData, err := json.Marshal(r)
	c.Assert(err, IsNil)

	newRule := Rule{}
	err = json.Unmarshal(jsonData, &newRule)
	c.Assert(err, IsNil)

	c.Check(newRule.EndpointSelector.LabelSelector == nil, Equals, r.EndpointSelector.LabelSelector == nil)
	c.Check(newRule.NodeSelector.LabelSelector == nil, Equals, r.NodeSelector.LabelSelector == nil)
}

// This test ensures that the NodeSelector and EndpointSelector fields are kept
// empty when the rule is marshalled/unmarshalled.
func (s *PolicyAPITestSuite) TestJSONMarshalling(c *C) {
	validEndpointRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(c, &validEndpointRule)

	validNodeRule := Rule{
		NodeSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(c, &validNodeRule)
}
