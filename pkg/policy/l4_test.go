// Copyright 2017 Authors of Cilium
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

package policy

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func (s *PolicyTestSuite) testDPortCoverage(c *C, policy L4Policy,
	covers func([]*models.Port) api.Decision) {

	ports := []*models.Port{}
	c.Assert(covers(ports), Equals, api.Denied)

	// Policy should match all of the below ports.
	ports = []*models.Port{
		{
			Port:     8080,
			Protocol: "tcp",
		},
	}
	c.Assert(covers(ports), Equals, api.Allowed)

	// Adding another port outside the policy will now be denied.
	ports = append(ports, &models.Port{Port: 8080, Protocol: "udp"})
	c.Assert(covers(ports), Equals, api.Denied)

	// Ports with protocol any should match the TCP policy above.
	ports = []*models.Port{
		{
			Port:     8080,
			Protocol: "any",
		},
	}
	c.Assert(covers(ports), Equals, api.Allowed)
}

func (s *PolicyTestSuite) TestIngressCoversDPorts(c *C) {
	policy := L4Policy{}

	// Empty policy allows traffic
	c.Assert(policy.IngressCoversDPorts([]*models.Port{}), Equals, api.Allowed)

	// Non-empty policy denies traffic without a port specified
	policy = L4Policy{
		Ingress: L4PolicyMap{
			"8080/tcp": {
				Port:     8080,
				Protocol: "tcp",
				Ingress:  true,
			},
		},
	}
	s.testDPortCoverage(c, policy, policy.IngressCoversDPorts)
}

func (s *PolicyTestSuite) TestEgressCoversDPorts(c *C) {
	policy := L4Policy{}

	// Empty policy allows traffic
	c.Assert(policy.EgressCoversDPorts([]*models.Port{}), Equals, api.Allowed)

	// Non-empty policy denies traffic without a port specified
	policy = L4Policy{
		Egress: L4PolicyMap{
			"8080/tcp": {
				Port:     8080,
				Protocol: "tcp",
				Ingress:  false,
			},
		},
	}
	s.testDPortCoverage(c, policy, policy.EgressCoversDPorts)
}
