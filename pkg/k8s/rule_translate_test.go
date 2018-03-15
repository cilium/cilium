// Copyright 2016-2017 Authors of Cilium
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

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api/v2"

	. "gopkg.in/check.v1"
)

func (s *K8sSuite) TestTranslatorDirect(c *C) {
	repo := policy.NewPolicyRepository()

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := types.K8sServiceNamespace{
		ServiceName: "svc",
		Namespace:   "default",
	}

	epIP := "10.1.1.1"

	endpointInfo := types.K8sServiceEndpoint{
		BEIPs: map[string]bool{
			epIP: true,
		},
		Ports: map[types.FEPortName]*types.L4Addr{
			"port": {
				Protocol: types.TCP,
				Port:     80,
			},
		},
	}

	rule1 := v2.Rule{
		EndpointSelector: v2.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []v2.EgressRule{
			{
				ToServices: []v2.Service{
					{
						K8sService: &v2.K8sServiceNamespace{
							ServiceName: serviceInfo.ServiceName,
							Namespace:   serviceInfo.Namespace,
						},
					},
				},
			},
		},
		Labels: tag1,
	}

	translator := NewK8sTranslator(serviceInfo, endpointInfo, false, map[string]string{})

	_, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	err = repo.TranslateRules(translator)
	c.Assert(err, IsNil)

	rule := repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	translator = NewK8sTranslator(serviceInfo, endpointInfo, true, map[string]string{})
	err = repo.TranslateRules(translator)

	rule = repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
}

func (s *K8sSuite) TestTranslatorLabels(c *C) {
	repo := policy.NewPolicyRepository()
	svcLabels := map[string]string{
		"app": "tested-service",
	}

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := types.K8sServiceNamespace{
		ServiceName: "doesn't matter",
		Namespace:   "default",
	}

	epIP := "10.1.1.1"

	endpointInfo := types.K8sServiceEndpoint{
		BEIPs: map[string]bool{
			epIP: true,
		},
		Ports: map[types.FEPortName]*types.L4Addr{
			"port": {
				Protocol: types.TCP,
				Port:     80,
			},
		},
	}

	selector := v2.ServiceSelector{
		LabelSelector: &metav1.LabelSelector{
			MatchLabels: svcLabels,
		},
	}

	rule1 := v2.Rule{
		EndpointSelector: v2.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []v2.EgressRule{{
			ToServices: []v2.Service{
				{
					K8sServiceSelector: &v2.K8sServiceSelectorNamespace{
						Selector:  selector,
						Namespace: "",
					},
				},
			}},
		},
		Labels: tag1,
	}

	translator := NewK8sTranslator(serviceInfo, endpointInfo, false, svcLabels)

	_, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	err = repo.TranslateRules(translator)
	c.Assert(err, IsNil)

	rule := repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	translator = NewK8sTranslator(serviceInfo, endpointInfo, true, svcLabels)
	err = repo.TranslateRules(translator)

	rule = repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
}

func (s *K8sSuite) TestGenerateToCIDRFromEndpoint(c *C) {
	rule := &v2.EgressRule{}

	epIP := "10.1.1.1"

	endpointInfo := types.K8sServiceEndpoint{
		BEIPs: map[string]bool{
			epIP: true,
		},
		Ports: map[types.FEPortName]*types.L4Addr{
			"port": {
				Protocol: types.TCP,
				Port:     80,
			},
		},
	}

	err := generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	// second run, to make sure there are no duplicates added
	err = generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	err = deleteToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
}

func (s *K8sSuite) TestPreprocessRules(c *C) {
	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := types.K8sServiceNamespace{
		ServiceName: "svc",
		Namespace:   "default",
	}

	epIP := "10.1.1.1"

	endpointInfo := types.K8sServiceEndpoint{
		BEIPs: map[string]bool{
			epIP: true,
		},
		Ports: map[types.FEPortName]*types.L4Addr{
			"port": {
				Protocol: types.TCP,
				Port:     80,
			},
		},
	}

	service := types.K8sServiceInfo{
		IsHeadless: true,
	}

	rule1 := v2.Rule{
		EndpointSelector: v2.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []v2.EgressRule{{
			ToServices: []v2.Service{
				{
					K8sService: &v2.K8sServiceNamespace{
						ServiceName: serviceInfo.ServiceName,
						Namespace:   serviceInfo.Namespace,
					},
				},
			}},
		},
		Labels: tag1,
	}

	endpoints := map[types.K8sServiceNamespace]*types.K8sServiceEndpoint{
		serviceInfo: &endpointInfo,
	}

	services := map[types.K8sServiceNamespace]*types.K8sServiceInfo{
		serviceInfo: &service,
	}

	rules := v2.Rules{&rule1}

	err := PreprocessRules(rules, endpoints, services)
	c.Assert(err, IsNil)

	c.Assert(len(rule1.Egress[0].ToCIDRSet), Equals, 1)
	c.Assert(string(rule1.Egress[0].ToCIDRSet[0].Cidr), Equals, epIP+"/32")
}

func (s *K8sSuite) TestDontDeleteUserRules(c *C) {
	userCIDR := v2.CIDR("10.1.1.2/32")
	rule := &v2.EgressRule{
		ToCIDRSet: []v2.CIDRRule{
			{
				Cidr: userCIDR,
			},
		},
	}

	epIP := "10.1.1.1"

	endpointInfo := types.K8sServiceEndpoint{
		BEIPs: map[string]bool{
			epIP: true,
		},
		Ports: map[types.FEPortName]*types.L4Addr{
			"port": {
				Protocol: types.TCP,
				Port:     80,
			},
		},
	}

	err := generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 2)
	c.Assert(string(rule.ToCIDRSet[1].Cidr), Equals, epIP+"/32")

	// second run, to make sure there are no duplicates added
	err = generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 2)
	c.Assert(string(rule.ToCIDRSet[1].Cidr), Equals, epIP+"/32")

	err = deleteToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, string(userCIDR))
}
