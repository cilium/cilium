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

package main

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/checker"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func getSamplePolicy(name, ns string) *cilium_v2.CiliumNetworkPolicy {
	cnp := &cilium_v2.CiliumNetworkPolicy{}

	cnp.ObjectMeta.Name = name
	cnp.ObjectMeta.Namespace = ns
	cnp.ObjectMeta.UID = types.UID("123")
	cnp.Spec = &api.Rule{
		EndpointSelector: api.EndpointSelector{
			LabelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"test": "true",
				},
			},
		},
	}
	return cnp
}

func (s *OperatorTestSuite) TestCorrectDerivativeName(c *C) {
	name := "test"
	cnp := getSamplePolicy(name, "testns")
	DerivativeCNP, err := createDerivativeCNP(cnp)
	c.Assert(err, IsNil)
	c.Assert(
		DerivativeCNP.ObjectMeta.Name,
		Equals,
		fmt.Sprintf("%s-togroups-%s", name, cnp.ObjectMeta.UID))
}

func (s *OperatorTestSuite) TestDerivativePoliciesAreDeletedIfNoToGroups(c *C) {
	name := "test"
	cnp := getSamplePolicy(name, "testns")

	cnp.Spec.Egress = []api.EgressRule{
		{
			ToPorts: []api.PortRule{
				{
					Ports: []api.PortProtocol{
						{Port: "5555"},
					},
				},
			},
		},
	}

	DerivativeCNP, err := createDerivativeCNP(cnp)
	c.Assert(err, IsNil)
	c.Assert(DerivativeCNP.Specs[0].Egress, checker.DeepEquals, cnp.Spec.Egress)
	c.Assert(len(DerivativeCNP.Specs), Equals, 1)
}

func (s *OperatorTestSuite) TestDerivativePoliciesAreInheritCorrectly(c *C) {

	cb := func(group *api.ToGroups) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.168.1.1")}, nil
	}

	api.RegisterToGroupsProvider(api.AWSProvider, cb)

	name := "test"
	cnp := getSamplePolicy(name, "testns")

	cnp.Spec.Egress = []api.EgressRule{
		{
			ToPorts: []api.PortRule{
				{
					Ports: []api.PortProtocol{
						{Port: "5555"},
					},
				},
			},
			ToGroups: []api.ToGroups{
				{
					AWS: &api.AWSGroup{
						Labels: map[string]string{
							"test": "a",
						},
					},
				},
			},
		},
	}

	DerivativeCNP, err := createDerivativeCNP(cnp)
	c.Assert(err, IsNil)
	c.Assert(DerivativeCNP.Spec, IsNil)
	c.Assert(len(DerivativeCNP.Specs), Equals, 1)
	c.Assert(DerivativeCNP.Specs[0].Egress[0].ToPorts, checker.DeepEquals, cnp.Spec.Egress[0].ToPorts)
	c.Assert(len(DerivativeCNP.Specs[0].Egress[0].ToGroups), Equals, 0)
}
