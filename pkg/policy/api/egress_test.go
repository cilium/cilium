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

// +build !privileged_tests

package api

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *PolicyAPITestSuite) TestRequiresDerivativeRuleWithoutToGroups(c *C) {
	eg := EgressRule{}
	c.Assert(eg.RequiresDerivative(), Equals, false)
}

func (s *PolicyAPITestSuite) TestRequiresDerivativeRuleWithToGroups(c *C) {
	eg := EgressRule{}
	eg.ToGroups = []ToGroups{
		GetToGroupsRule(),
	}
	c.Assert(eg.RequiresDerivative(), Equals, true)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeRuleWithoutToGroups(c *C) {
	eg := &EgressRule{
		ToEndpoints: []EndpointSelector{
			{
				LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
					"test": "true",
				},
				},
			},
		},
	}
	newRule, err := eg.CreateDerivative()
	c.Assert(eg, checker.DeepEquals, newRule)
	c.Assert(err, IsNil)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeRuleWithToGroupsWitInvalidRegisterCallback(c *C) {
	cb := func(group *ToGroups) ([]net.IP, error) {
		return []net.IP{}, fmt.Errorf("Invalid error")
	}
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		ToGroups: []ToGroups{
			GetToGroupsRule(),
		},
	}
	_, err := eg.CreateDerivative()
	c.Assert(err, NotNil)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeRuleWithToGroupsAndToPorts(c *C) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		ToGroups: []ToGroups{
			GetToGroupsRule(),
		},
	}

	// Checking that the derivative rule is working correctly
	c.Assert(eg.RequiresDerivative(), Equals, true)

	newRule, err := eg.CreateDerivative()
	c.Assert(err, IsNil)
	c.Assert(len(newRule.ToGroups), Equals, 0)
	c.Assert(len(newRule.ToCIDRSet), Equals, 1)
}

func (s *PolicyAPITestSuite) TestCreateDerivativeWithoutErrorAndNoIPs(c *C) {
	// Testing that if the len of the Ips returned by provider is 0 to block
	// all the IPS outside.
	cb := GetCallBackWithRule()
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		ToGroups: []ToGroups{
			GetToGroupsRule(),
		},
	}

	// Checking that the derivative rule is working correctly
	c.Assert(eg.RequiresDerivative(), Equals, true)

	newRule, err := eg.CreateDerivative()
	c.Assert(err, IsNil)
	c.Assert(newRule, checker.DeepEquals, &EgressRule{})
}
