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
	"net"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

func (s *PolicyAPITestSuite) TestK8sServiceNamespaceMatches(c *C) {
	type testDef struct {
		id           K8sServiceIdentifier
		sel          K8sServiceNamespace
		expectResult bool
	}

	tests := []testDef{
		{
			id:           NewK8sServiceIdentifier("svc1", "default", map[string]string{"foo": "bar"}),
			sel:          K8sServiceNamespace{ServiceName: "svc1", Namespace: "default"},
			expectResult: true,
		},
		{
			id:           NewK8sServiceIdentifier("svc2", "default", map[string]string{"foo": "bar"}),
			sel:          K8sServiceNamespace{ServiceName: "svc1", Namespace: "default"},
			expectResult: false,
		},
		{
			id:           NewK8sServiceIdentifier("svc1", "other", map[string]string{"foo": "bar"}),
			sel:          K8sServiceNamespace{ServiceName: "svc1", Namespace: "default"},
			expectResult: false,
		},
		{
			id:           K8sServiceIdentifier{},
			sel:          K8sServiceNamespace{ServiceName: "svc1", Namespace: "default"},
			expectResult: false,
		},
	}

	for _, test := range tests {
		c.Assert(test.sel.Matches(test.id), Equals, test.expectResult)
	}
}

func (s *PolicyAPITestSuite) TestK8sServiceSelectorNamespaceMatches(c *C) {
	type testDef struct {
		id           K8sServiceIdentifier
		sel          K8sServiceSelectorNamespace
		expectResult bool
	}

	tests := []testDef{
		{
			id:           NewK8sServiceIdentifier("svc1", "default", map[string]string{"foo": "bar"}),
			sel:          K8sServiceSelectorNamespace{Namespace: "default", Selector: NewServiceSelectorFromMatchLabels(map[string]string{"foo": "bar"})},
			expectResult: true,
		},
		{
			id:           NewK8sServiceIdentifier("svc1", "default", map[string]string{"foo": "bar", "foo2": "bar"}),
			sel:          K8sServiceSelectorNamespace{Namespace: "default", Selector: NewServiceSelectorFromMatchLabels(map[string]string{"foo": "bar"})},
			expectResult: true,
		},
		{
			id:           NewK8sServiceIdentifier("svc1", "default", map[string]string{"foo": "bar"}),
			sel:          K8sServiceSelectorNamespace{Namespace: "default", Selector: NewServiceSelectorFromMatchLabels(map[string]string{"foo": "bar2"})},
			expectResult: false,
		},
		{
			id:           NewK8sServiceIdentifier("svc1", "default2", map[string]string{"foo": "bar"}),
			sel:          K8sServiceSelectorNamespace{Namespace: "default", Selector: NewServiceSelectorFromMatchLabels(map[string]string{"foo": "bar"})},
			expectResult: false,
		},
		{
			id:           NewK8sServiceIdentifier("svc1", "default2", map[string]string{"foo": "bar"}),
			sel:          K8sServiceSelectorNamespace{Namespace: "", Selector: NewServiceSelectorFromMatchLabels(map[string]string{"foo": "bar"})},
			expectResult: true,
		},
	}

	for _, test := range tests {
		c.Assert(test.sel.Matches(test.id), Equals, test.expectResult)
	}
}

func (s *PolicyAPITestSuite) TestK8sServiceMatches(c *C) {
	type testDef struct {
		id           K8sServiceIdentifier
		sel          Service
		expectResult bool
	}

	tests := []testDef{
		{
			id: NewK8sServiceIdentifier("svc1", "default", map[string]string{"foo": "bar"}),
			// Test combined match of K8sServiceNamespace and K8sServiceSelector
			sel: Service{
				K8sService: &K8sServiceNamespace{
					ServiceName: "svc1",
					Namespace:   "default",
				},
				K8sServiceSelector: &K8sServiceSelectorNamespace{
					Namespace: "default",
					Selector:  NewServiceSelectorFromMatchLabels(map[string]string{"foo": "bar"}),
				},
			},
			expectResult: true,
		},
		{
			id: NewK8sServiceIdentifier("svc1", "default", map[string]string{"foo2": "bar"}),
			sel: Service{
				K8sServiceSelector: &K8sServiceSelectorNamespace{
					Namespace: "default",
					Selector:  NewServiceSelectorFromMatchLabels(map[string]string{"foo": "bar"}),
				},
			},
			expectResult: false,
		},
	}

	for _, test := range tests {
		c.Assert(test.sel.Matches(test.id), Equals, test.expectResult)
	}
}

func (s *PolicyAPITestSuite) TestK8sServiceGetCidrSet(c *C) {
	svc := Service{}

	ips := svc.GetCidrSet()
	c.Assert(ips, IsNil)

	RegisterServiceProvider("test-provider", func(svc *Service) []net.IP {
		return []net.IP{net.ParseIP("1.1.1.1")}
	})

	ips = svc.GetCidrSet()
	c.Assert(ips, checker.DeepEquals, []CIDRRule{{Cidr: "1.1.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true}})

	UnregisterServiceProvider("test-provider")
}
