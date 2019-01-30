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

// +build !privileged_tests

package k8s

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/service"

	. "gopkg.in/check.v1"
)

func (s *K8sSuite) TestTranslatorDirect(c *C) {
	repo := policy.NewPolicyRepository()

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := ServiceID{
		Name:      "svc",
		Namespace: "default",
	}

	epIP := "10.1.1.1"

	endpointInfo := Endpoints{
		Backends: map[string]service.PortConfiguration{
			epIP: map[string]*loadbalancer.L4Addr{
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{
			{
				ToServices: []api.Service{
					{
						K8sService: &api.K8sServiceNamespace{
							ServiceName: serviceInfo.Name,
							Namespace:   serviceInfo.Namespace,
						},
					},
				},
			},
		},
		Labels: tag1,
	}

	translator := NewK8sTranslator(serviceInfo, endpointInfo, false, map[string]string{}, nil)

	_, _, err := repo.Add(rule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	result, err := repo.TranslateRules(translator)
	c.Assert(err, IsNil)
	c.Assert(result.NumToServicesRules, Equals, 1)

	rule := repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	translator = NewK8sTranslator(serviceInfo, endpointInfo, true, map[string]string{}, nil)
	result, err = repo.TranslateRules(translator)
	c.Assert(result.NumToServicesRules, Equals, 1)

	rule = repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
}

func (s *K8sSuite) TestServiceMatches(c *C) {
	svcLabels := map[string]string{
		"app": "tested-service",
	}

	serviceInfo := ServiceID{
		Name:      "doesn't matter",
		Namespace: "default",
	}

	epIP := "10.1.1.1"
	endpointInfo := Endpoints{
		Backends: map[string]service.PortConfiguration{
			epIP: map[string]*loadbalancer.L4Addr{
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	selector := api.ServiceSelector(api.NewESFromMatchRequirements(svcLabels, nil))
	service := api.Service{
		K8sServiceSelector: &api.K8sServiceSelectorNamespace{
			Selector:  selector,
			Namespace: "",
		},
	}

	translator := NewK8sTranslator(serviceInfo, endpointInfo, false, svcLabels, nil)
	c.Assert(translator.serviceMatches(service), Equals, true)
}

func (s *K8sSuite) TestTranslatorLabels(c *C) {
	repo := policy.NewPolicyRepository()
	svcLabels := map[string]string{
		"app": "tested-service",
	}

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := ServiceID{
		Name:      "doesn't matter",
		Namespace: "default",
	}

	epIP := "10.1.1.1"

	endpointInfo := Endpoints{
		Backends: map[string]service.PortConfiguration{
			epIP: map[string]*loadbalancer.L4Addr{
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	selector := api.ServiceSelector(api.NewESFromMatchRequirements(svcLabels, nil))
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{{
			ToServices: []api.Service{
				{
					K8sServiceSelector: &api.K8sServiceSelectorNamespace{
						Selector:  selector,
						Namespace: "",
					},
				},
			}},
		},
		Labels: tag1,
	}

	translator := NewK8sTranslator(serviceInfo, endpointInfo, false, svcLabels, nil)

	_, _, err := repo.Add(rule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	result, err := repo.TranslateRules(translator)
	c.Assert(err, IsNil)
	c.Assert(result.NumToServicesRules, Equals, 1)

	rule := repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	translator = NewK8sTranslator(serviceInfo, endpointInfo, true, svcLabels, nil)
	result, err = repo.TranslateRules(translator)

	rule = repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
	c.Assert(result.NumToServicesRules, Equals, 1)
}

func (s *K8sSuite) TestGenerateToCIDRFromEndpoint(c *C) {
	rule := &api.EgressRule{}

	epIP := "10.1.1.1"

	endpointInfo := Endpoints{
		Backends: map[string]service.PortConfiguration{
			epIP: map[string]*loadbalancer.L4Addr{
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	err := generateToCidrFromEndpoint(rule, endpointInfo, nil)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	// second run, to make sure there are no duplicates added
	err = generateToCidrFromEndpoint(rule, endpointInfo, nil)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epIP+"/32")

	err = deleteToCidrFromEndpoint(rule, endpointInfo, nil)
	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
}

func (s *K8sSuite) TestPreprocessRules(c *C) {
	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := ServiceID{
		Name:      "svc",
		Namespace: "default",
	}

	epIP := "10.1.1.1"

	cache := NewServiceCache()

	endpointInfo := Endpoints{
		Backends: map[string]service.PortConfiguration{
			epIP: map[string]*loadbalancer.L4Addr{
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	service := Service{IsHeadless: true}

	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{{
			ToServices: []api.Service{
				{
					K8sService: &api.K8sServiceNamespace{
						ServiceName: serviceInfo.Name,
						Namespace:   serviceInfo.Namespace,
					},
				},
			}},
		},
		Labels: tag1,
	}

	cache.endpoints = map[ServiceID]*Endpoints{
		serviceInfo: &endpointInfo,
	}

	cache.services = map[ServiceID]*Service{
		serviceInfo: &service,
	}

	rules := api.Rules{&rule1}

	err := PreprocessRules(rules, &cache)
	c.Assert(err, IsNil)

	c.Assert(len(rule1.Egress[0].ToCIDRSet), Equals, 1)
	c.Assert(string(rule1.Egress[0].ToCIDRSet[0].Cidr), Equals, epIP+"/32")
}

func (s *K8sSuite) TestDontDeleteUserRules(c *C) {
	userCIDR := api.CIDR("10.1.1.2/32")
	rule := &api.EgressRule{
		ToCIDRSet: []api.CIDRRule{
			{
				Cidr: userCIDR,
			},
		},
	}

	epIP := "10.1.1.1"

	endpointInfo := Endpoints{
		Backends: map[string]service.PortConfiguration{
			epIP: map[string]*loadbalancer.L4Addr{
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	err := generateToCidrFromEndpoint(rule, endpointInfo, nil)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 2)
	c.Assert(string(rule.ToCIDRSet[1].Cidr), Equals, epIP+"/32")

	// second run, to make sure there are no duplicates added
	err = generateToCidrFromEndpoint(rule, endpointInfo, nil)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 2)
	c.Assert(string(rule.ToCIDRSet[1].Cidr), Equals, epIP+"/32")

	err = deleteToCidrFromEndpoint(rule, endpointInfo, nil)
	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, string(userCIDR))
}
