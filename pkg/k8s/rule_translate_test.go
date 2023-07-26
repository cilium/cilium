// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"net"
	"net/netip"
	"sort"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/checker"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

func TestTranslate(t *testing.T) {
	type args struct {
		rule   *api.Rule
		result *policy.TranslationResult
	}
	type translator struct {
		sid            ServiceID
		oldEPs, newEPs Endpoints
		revert         bool
		labels         map[string]string
	}
	epAddrCluster := cmtypes.MustParseAddrCluster("10.1.1.1")
	epAddrCluster2 := cmtypes.MustParseAddrCluster("10.2.1.1")
	defaultTranslator := translator{
		sid: ServiceID{
			Cluster:   "1",
			Name:      "foo",
			Namespace: "default",
		},
		oldEPs: Endpoints{
			Backends: map[cmtypes.AddrCluster]*Backend{
				epAddrCluster: {
					Ports: map[string]*loadbalancer.L4Addr{
						"port": {
							Protocol: loadbalancer.TCP,
							Port:     80,
						},
					},
				},
			},
		},
		newEPs: Endpoints{
			Backends: map[cmtypes.AddrCluster]*Backend{
				epAddrCluster2: {
					Ports: map[string]*loadbalancer.L4Addr{
						"port": {
							Protocol: loadbalancer.TCP,
							Port:     80,
						},
					},
				},
			},
		},
		revert: false,
		labels: map[string]string{
			"app": "foo",
		},
	}
	defaultRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDRSet: api.CIDRRuleSlice{
						{Cidr: api.CIDR(epAddrCluster.String() + "/32"), Generated: true},
					},
					ToServices: []api.Service{
						{
							K8sService: &api.K8sServiceNamespace{
								ServiceName: defaultTranslator.sid.Name,
								Namespace:   defaultTranslator.sid.Namespace,
							},
						},
					},
				},
			},
		},
	}
	tests := []struct {
		name           string
		translator     func() translator
		args           func() args
		expected       error
		expectedResult *policy.TranslationResult
	}{
		{
			name:       "both prefixes to add and remove",
			translator: func() translator { return defaultTranslator },
			args: func() args {
				return args{
					rule:   defaultRule.DeepCopy(),
					result: &policy.TranslationResult{},
				}
			},
			expected: nil,
			expectedResult: &policy.TranslationResult{
				NumToServicesRules: 1,
				PrefixesToRelease:  []netip.Prefix{netip.PrefixFrom(epAddrCluster.Addr(), 32)},
				PrefixesToAdd:      []netip.Prefix{netip.PrefixFrom(epAddrCluster2.Addr(), 32)},
			},
		},
		{
			name: "only prefix to release",
			translator: func() translator {
				n := defaultTranslator
				n.oldEPs.Backends[epAddrCluster2] = &Backend{
					Ports: map[string]*loadbalancer.L4Addr{
						"port": {
							Protocol: loadbalancer.TCP,
							Port:     80,
						},
					},
				}
				return n
			},
			args: func() args {
				r := defaultRule.DeepCopy()
				r.Egress[0].ToCIDRSet = append(r.Egress[0].ToCIDRSet, api.CIDRRule{
					Cidr:      api.CIDR(epAddrCluster2.String() + "/32"),
					Generated: true,
				})
				return args{
					rule:   r,
					result: &policy.TranslationResult{},
				}
			},
			expected: nil,
			expectedResult: &policy.TranslationResult{
				NumToServicesRules: 1,
				PrefixesToRelease:  []netip.Prefix{netip.PrefixFrom(epAddrCluster.Addr(), 32)},
				PrefixesToAdd:      nil,
			},
		},
		{
			name: "no prefixes to add or remove",
			translator: func() translator {
				n := defaultTranslator
				n.oldEPs.Backends[epAddrCluster2] = &Backend{
					Ports: map[string]*loadbalancer.L4Addr{
						"port": {
							Protocol: loadbalancer.TCP,
							Port:     80,
						},
					},
				}
				n.newEPs = n.oldEPs
				return n
			},
			args: func() args {
				r := defaultRule.DeepCopy()
				r.Egress[0].ToCIDRSet = append(r.Egress[0].ToCIDRSet, api.CIDRRule{
					Cidr:      api.CIDR(epAddrCluster2.String() + "/32"),
					Generated: true,
				})
				return args{
					rule:   r,
					result: &policy.TranslationResult{},
				}
			},
			expected: nil,
			expectedResult: &policy.TranslationResult{
				NumToServicesRules: 1,
				PrefixesToRelease:  nil,
				PrefixesToAdd:      nil,
			},
		},
		{
			name: "only prefix to add",
			translator: func() translator {
				n := defaultTranslator
				n.newEPs.Backends[epAddrCluster] = &Backend{
					Ports: map[string]*loadbalancer.L4Addr{
						"port": {
							Protocol: loadbalancer.TCP,
							Port:     80,
						},
					},
				}
				return n
			},
			args: func() args {
				return args{
					rule:   defaultRule.DeepCopy(),
					result: &policy.TranslationResult{},
				}
			},
			expected: nil,
			expectedResult: &policy.TranslationResult{
				NumToServicesRules: 1,
				PrefixesToRelease:  nil,
				PrefixesToAdd:      []netip.Prefix{netip.PrefixFrom(epAddrCluster2.Addr(), 32)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lator := tt.translator()
			args := tt.args()
			tr := NewK8sTranslator(lator.sid, lator.oldEPs, lator.newEPs, lator.labels)
			err := tr.Translate(args.rule, args.result)
			assert.Equal(t, tt.expected, err)
			assert.Equal(t, tt.expectedResult, args.result)
		})
	}
}

func (s *K8sSuite) TestTranslatorDirect(c *C) {
	idAllocator := testidentity.NewMockIdentityAllocator(nil)
	repo := policy.NewPolicyRepository(idAllocator, nil, nil, nil)

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := ServiceID{
		Name:      "svc",
		Namespace: "default",
	}

	epAddrCluster := cmtypes.MustParseAddrCluster("10.1.1.1")

	endpointInfo := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			epAddrCluster: {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}

	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
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
		},
		Labels: tag1,
	}

	translator := NewK8sTranslator(serviceInfo, Endpoints{}, endpointInfo, map[string]string{})

	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	result, err := repo.TranslateRules(translator)
	c.Assert(err, IsNil)
	c.Assert(result.NumToServicesRules, Equals, 1)

	rule := repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epAddrCluster.Addr().String()+"/32")

	translator = NewK8sTranslator(serviceInfo, endpointInfo, Endpoints{}, map[string]string{})
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

	epAddrCluster := cmtypes.MustParseAddrCluster("10.1.1.1")
	endpointInfo := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			epAddrCluster: {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
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

	translator := NewK8sTranslator(serviceInfo, Endpoints{}, endpointInfo, svcLabels)
	c.Assert(translator.serviceMatches(service), Equals, true)
}

func (s *K8sSuite) TestTranslatorLabels(c *C) {
	idAllocator := testidentity.NewMockIdentityAllocator(nil)
	repo := policy.NewPolicyRepository(idAllocator, nil, nil, nil)
	svcLabels := map[string]string{
		"app": "tested-service",
	}

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := ServiceID{
		Name:      "doesn't matter",
		Namespace: "default",
	}

	epAddrCluster := cmtypes.MustParseAddrCluster("10.1.1.1")

	endpointInfo := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			epAddrCluster: {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}

	selector := api.ServiceSelector(api.NewESFromMatchRequirements(svcLabels, nil))
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToServices: []api.Service{
					{
						K8sServiceSelector: &api.K8sServiceSelectorNamespace{
							Selector:  selector,
							Namespace: "",
						},
					},
				},
			}},
		},
		Labels: tag1,
	}

	translator := NewK8sTranslator(serviceInfo, Endpoints{}, endpointInfo, svcLabels)

	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	result, err := repo.TranslateRules(translator)
	c.Assert(err, IsNil)
	c.Assert(result.NumToServicesRules, Equals, 1)

	rule := repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, epAddrCluster.Addr().String()+"/32")

	translator = NewK8sTranslator(serviceInfo, endpointInfo, Endpoints{}, svcLabels)
	result, err = repo.TranslateRules(translator)

	rule = repo.SearchRLocked(tag1)[0].Egress[0]

	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
	c.Assert(result.NumToServicesRules, Equals, 1)
}

func (s *K8sSuite) TestGenerateToCIDRFromEndpoint(c *C) {
	rule := &api.EgressRule{}

	epAddrCluster1 := cmtypes.MustParseAddrCluster("10.1.1.1")
	epAddrCluster2 := cmtypes.MustParseAddrCluster("10.1.1.2")

	endpointInfo := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			epAddrCluster1: {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
			epAddrCluster2: {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}
	serviceInfo := ServiceID{
		Name:      "svc",
		Namespace: "default",
	}

	translator := NewK8sTranslator(serviceInfo, Endpoints{}, endpointInfo, map[string]string{})
	_, err := translator.generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)
	cidrs := rule.ToCIDRSet.StringSlice()
	sort.Strings(cidrs)
	c.Assert(len(cidrs), Equals, 2)
	c.Assert(cidrs, checker.DeepEquals, []string{
		epAddrCluster1.Addr().String() + "/32",
		epAddrCluster2.Addr().String() + "/32",
	})

	// second run, to make sure there are no duplicates added
	prefixesToAllocate, err := translator.generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)
	_, epIP1Prefix, err := net.ParseCIDR(epAddrCluster1.Addr().String() + "/32")
	c.Assert(err, IsNil)
	_, epIP2Prefix, err := net.ParseCIDR(epAddrCluster2.Addr().String() + "/32")
	c.Assert(err, IsNil)
	prefixStrings := []string{}
	for _, ipnet := range prefixesToAllocate {
		prefixStrings = append(prefixStrings, ipnet.String())
	}
	c.Assert(len(prefixesToAllocate), Equals, 2)
	sort.Strings(prefixStrings)
	c.Assert(prefixStrings[0], Equals, epIP1Prefix.String())
	c.Assert(prefixStrings[1], Equals, epIP2Prefix.String())

	cidrs = rule.ToCIDRSet.StringSlice()
	sort.Strings(cidrs)
	c.Assert(len(cidrs), Equals, 2)
	c.Assert(cidrs, checker.DeepEquals, []string{
		epAddrCluster1.Addr().String() + "/32",
		epAddrCluster2.Addr().String() + "/32",
	})

	_, err = translator.deleteToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)

	// third run, to make sure there are no duplicates added
	_, err = translator.generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)

	cidrs = rule.ToCIDRSet.StringSlice()
	sort.Strings(cidrs)
	c.Assert(len(cidrs), Equals, 2)
	c.Assert(cidrs, checker.DeepEquals, []string{
		epAddrCluster1.Addr().String() + "/32",
		epAddrCluster2.Addr().String() + "/32",
	})

	// and one final delete
	_, err = translator.deleteToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 0)
}

func (s *K8sSuite) TestPreprocessRules(c *C) {
	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	serviceInfo := ServiceID{
		Name:      "svc",
		Namespace: "default",
	}

	epAddrCluster := cmtypes.MustParseAddrCluster("10.1.1.1")

	cache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	endpointInfo := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			epAddrCluster: {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}

	service := Service{IsHeadless: true}

	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToServices: []api.Service{
					{
						K8sService: &api.K8sServiceNamespace{
							ServiceName: serviceInfo.Name,
							Namespace:   serviceInfo.Namespace,
						},
					},
				},
			}},
		},
		Labels: tag1,
	}

	cache.endpoints = map[ServiceID]*EndpointSlices{
		serviceInfo: {
			epSlices: map[string]*Endpoints{
				"": &endpointInfo,
			},
		},
	}

	cache.services = map[ServiceID]*Service{
		serviceInfo: &service,
	}

	rules := api.Rules{&rule1}

	err := PreprocessRules(rules, cache)
	c.Assert(err, IsNil)

	c.Assert(len(rule1.Egress[0].ToCIDRSet), Equals, 1)
	c.Assert(string(rule1.Egress[0].ToCIDRSet[0].Cidr), Equals, epAddrCluster.Addr().String()+"/32")
}

func (s *K8sSuite) TestDontDeleteUserRules(c *C) {
	userCIDR := api.CIDR("10.1.1.2/32")
	rule := &api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDRSet: []api.CIDRRule{
				{
					Cidr: userCIDR,
				},
			},
		},
	}

	epAddrCluster := cmtypes.MustParseAddrCluster("10.1.1.1")

	endpointInfo := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			epAddrCluster: {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}
	serviceInfo := ServiceID{
		Name:      "svc",
		Namespace: "default",
	}

	translator := NewK8sTranslator(serviceInfo, Endpoints{}, endpointInfo, map[string]string{})
	_, err := translator.generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 2)
	c.Assert(string(rule.ToCIDRSet[1].Cidr), Equals, epAddrCluster.Addr().String()+"/32")

	// second run, to make sure there are no duplicates added
	_, err = translator.generateToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)

	c.Assert(len(rule.ToCIDRSet), Equals, 2)
	c.Assert(string(rule.ToCIDRSet[1].Cidr), Equals, epAddrCluster.Addr().String()+"/32")

	_, err = translator.deleteToCidrFromEndpoint(rule, endpointInfo)
	c.Assert(err, IsNil)
	c.Assert(len(rule.ToCIDRSet), Equals, 1)
	c.Assert(string(rule.ToCIDRSet[0].Cidr), Equals, string(userCIDR))
}
