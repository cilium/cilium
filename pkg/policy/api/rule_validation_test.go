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
	. "gopkg.in/check.v1"
)

// This test ensures that PortRules using the HTTP protocol have valid regular
// expressions for the method and path fields.
func (s *PolicyAPITestSuite) TestHTTPRuleRegexes(c *C) {

	invalidHTTPRegexPathRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "*"},
						},
					},
				}},
			},
		},
	}

	err := invalidHTTPRegexPathRule.Sanitize()
	c.Assert(err, Not(IsNil))

	invalidHTTPRegexMethodRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
		Ingress: []IngressRule{
			{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "*", Path: "/"},
						},
					},
				}},
			},
		},
	}

	err = invalidHTTPRegexMethodRule.Sanitize()
	c.Assert(err, Not(IsNil))
}
