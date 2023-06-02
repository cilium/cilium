// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	. "github.com/cilium/checkmate"
	"github.com/kr/pretty"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (s *PolicyTestSuite) TestRedirectType(c *C) {
	c.Assert(redirectTypeNone, Equals, redirectTypes(0))
	c.Assert(redirectTypeDNS, Equals, redirectTypes(0x1))
	c.Assert(redirectTypeEnvoy, Equals, redirectTypes(0x2))
	c.Assert(redirectTypeProxylib, Equals, redirectTypes(0x4)|redirectTypeEnvoy)
	c.Assert(redirectTypeProxylib&redirectTypeEnvoy, Equals, redirectTypeEnvoy)
}

func (s *PolicyTestSuite) TestParserTypeMerge(c *C) {
	for _, t := range []struct {
		a, b, c L7ParserType
		success bool
	}{
		// trivially true
		{ParserTypeNone, ParserTypeNone, ParserTypeNone, true},
		{ParserTypeDNS, ParserTypeDNS, ParserTypeDNS, true},
		{ParserTypeHTTP, ParserTypeHTTP, ParserTypeHTTP, true},
		{ParserTypeKafka, ParserTypeKafka, ParserTypeKafka, true},
		{L7ParserType("foo"), L7ParserType("foo"), L7ParserType("foo"), true},
		{ParserTypeTLS, ParserTypeTLS, ParserTypeTLS, true},

		// None can be promoted to any other type
		{ParserTypeNone, ParserTypeDNS, ParserTypeDNS, true},
		{ParserTypeDNS, ParserTypeNone, ParserTypeDNS, true},

		{ParserTypeNone, ParserTypeHTTP, ParserTypeHTTP, true},
		{ParserTypeHTTP, ParserTypeNone, ParserTypeHTTP, true},

		{ParserTypeNone, ParserTypeKafka, ParserTypeKafka, true},
		{ParserTypeKafka, ParserTypeNone, ParserTypeKafka, true},

		{ParserTypeNone, L7ParserType("foo"), L7ParserType("foo"), true},
		{L7ParserType("foo"), ParserTypeNone, L7ParserType("foo"), true},

		{ParserTypeNone, ParserTypeTLS, ParserTypeTLS, true},
		{ParserTypeTLS, ParserTypeNone, ParserTypeTLS, true},

		{ParserTypeNone, ParserTypeCRD, ParserTypeCRD, true},
		{ParserTypeCRD, ParserTypeNone, ParserTypeCRD, true},

		// None of the actual parser types can be promoted to CRD

		{ParserTypeHTTP, ParserTypeCRD, ParserTypeNone, false},
		{ParserTypeCRD, ParserTypeHTTP, ParserTypeNone, false},

		{ParserTypeTLS, ParserTypeCRD, ParserTypeNone, false},
		{ParserTypeCRD, ParserTypeTLS, ParserTypeNone, false},

		{ParserTypeKafka, ParserTypeCRD, ParserTypeNone, false},
		{ParserTypeCRD, ParserTypeKafka, ParserTypeNone, false},

		{L7ParserType("foo"), ParserTypeCRD, ParserTypeNone, false},
		{ParserTypeCRD, L7ParserType("foo"), ParserTypeNone, false},

		// TLS can also be promoted to any other type except for DNS (but not demoted to
		// None)

		{ParserTypeTLS, ParserTypeHTTP, ParserTypeHTTP, true},
		{ParserTypeHTTP, ParserTypeTLS, ParserTypeHTTP, true},

		{ParserTypeTLS, ParserTypeKafka, ParserTypeKafka, true},
		{ParserTypeKafka, ParserTypeTLS, ParserTypeKafka, true},

		{ParserTypeTLS, L7ParserType("foo"), L7ParserType("foo"), true},
		{L7ParserType("foo"), ParserTypeTLS, L7ParserType("foo"), true},

		// DNS does not merge with anything else

		{ParserTypeCRD, ParserTypeDNS, ParserTypeNone, false},
		{ParserTypeDNS, ParserTypeCRD, ParserTypeNone, false},

		{ParserTypeTLS, ParserTypeDNS, ParserTypeNone, false},
		{ParserTypeDNS, ParserTypeTLS, ParserTypeNone, false},

		{ParserTypeDNS, ParserTypeHTTP, ParserTypeNone, false},
		{ParserTypeHTTP, ParserTypeDNS, ParserTypeNone, false},

		{ParserTypeDNS, ParserTypeKafka, ParserTypeNone, false},
		{ParserTypeKafka, ParserTypeDNS, ParserTypeNone, false},

		{ParserTypeDNS, L7ParserType("foo"), ParserTypeNone, false},
		{L7ParserType("foo"), ParserTypeDNS, ParserTypeNone, false},

		// Proxylib parsers do not merge with other proxylib parsers nor with HTTP

		{ParserTypeKafka, ParserTypeHTTP, ParserTypeNone, false},
		{ParserTypeHTTP, ParserTypeKafka, ParserTypeNone, false},

		{L7ParserType("bar"), L7ParserType("foo"), ParserTypeNone, false},
		{L7ParserType("foo"), L7ParserType("bar"), ParserTypeNone, false},

		{L7ParserType("bar"), ParserTypeHTTP, ParserTypeNone, false},
		{ParserTypeHTTP, L7ParserType("bar"), ParserTypeNone, false},
	} {
		res, err := t.a.Merge(t.b)
		if t.success {
			c.Assert(err, Equals, nil)
		} else {
			c.Assert(err, Not(Equals), nil)
		}
		if res != t.c {
			fmt.Printf("Merge %s with %s, expecting %s\n", t.a, t.b, t.c)
		}
		c.Assert(res, Equals, t.c)
	}
}

func (s *PolicyTestSuite) TestCreateL4Filter(c *C) {
	tuple := api.PortProtocol{Port: "80", Protocol: api.ProtoTCP}
	portrule := &api.PortRule{
		Ports: []api.PortProtocol{tuple},
		Rules: &api.L7Rules{
			HTTP: []api.PortRuleHTTP{
				{Path: "/public", Method: "GET"},
			},
		},
	}
	selectors := []api.EndpointSelector{
		api.NewESFromLabels(),
		api.NewESFromLabels(labels.ParseSelectLabel("bar")),
	}

	for _, selector := range selectors {
		eps := []api.EndpointSelector{selector}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		filter, err := createL4IngressFilter(testPolicyContext, eps, nil, nil, portrule, tuple, tuple.Protocol, nil)
		c.Assert(err, IsNil)
		c.Assert(len(filter.PerSelectorPolicies), Equals, 1)
		for _, r := range filter.PerSelectorPolicies {
			c.Assert(r.GetAuthType(), Equals, AuthTypeNone)
		}
		c.Assert(filter.redirectType(), Equals, redirectTypeEnvoy)

		filter, err = createL4EgressFilter(testPolicyContext, eps, nil, portrule, tuple, tuple.Protocol, nil, nil)
		c.Assert(err, IsNil)
		c.Assert(len(filter.PerSelectorPolicies), Equals, 1)
		for _, r := range filter.PerSelectorPolicies {
			c.Assert(r.GetAuthType(), Equals, AuthTypeNone)
		}
		c.Assert(filter.redirectType(), Equals, redirectTypeEnvoy)
	}
}

func (s *PolicyTestSuite) TestCreateL4FilterAuthRequired(c *C) {
	tuple := api.PortProtocol{Port: "80", Protocol: api.ProtoTCP}
	portrule := &api.PortRule{
		Ports: []api.PortProtocol{tuple},
		Rules: &api.L7Rules{
			HTTP: []api.PortRuleHTTP{
				{Path: "/public", Method: "GET"},
			},
		},
	}
	selectors := []api.EndpointSelector{
		api.NewESFromLabels(),
		api.NewESFromLabels(labels.ParseSelectLabel("bar")),
	}

	auth := &api.Auth{Type: api.AuthTypeNull}
	for _, selector := range selectors {
		eps := []api.EndpointSelector{selector}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		filter, err := createL4IngressFilter(testPolicyContext, eps, auth, nil, portrule, tuple, tuple.Protocol, nil)
		c.Assert(err, IsNil)
		c.Assert(len(filter.PerSelectorPolicies), Equals, 1)
		for _, r := range filter.PerSelectorPolicies {
			c.Assert(r.GetAuthType(), Equals, AuthTypeNull)
		}
		c.Assert(filter.redirectType(), Equals, redirectTypeEnvoy)

		filter, err = createL4EgressFilter(testPolicyContext, eps, auth, portrule, tuple, tuple.Protocol, nil, nil)
		c.Assert(err, IsNil)
		c.Assert(len(filter.PerSelectorPolicies), Equals, 1)
		for _, r := range filter.PerSelectorPolicies {
			c.Assert(r.GetAuthType(), Equals, AuthTypeNull)
		}
		c.Assert(filter.redirectType(), Equals, redirectTypeEnvoy)
	}
}

func (s *PolicyTestSuite) TestCreateL4FilterMissingSecret(c *C) {
	tuple := api.PortProtocol{Port: "80", Protocol: api.ProtoTCP}
	portrule := &api.PortRule{
		Ports: []api.PortProtocol{tuple},
		TerminatingTLS: &api.TLSContext{
			Secret: &api.Secret{
				Name: "notExisting",
			},
		},
		Rules: &api.L7Rules{
			HTTP: []api.PortRuleHTTP{
				{Path: "/public", Method: "GET"},
			},
		},
	}
	selectors := []api.EndpointSelector{
		api.NewESFromLabels(),
		api.NewESFromLabels(labels.ParseSelectLabel("bar")),
	}

	for _, selector := range selectors {
		eps := []api.EndpointSelector{selector}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		_, err := createL4IngressFilter(testPolicyContext, eps, nil, nil, portrule, tuple, tuple.Protocol, nil)
		c.Assert(err, Not(IsNil))

		_, err = createL4EgressFilter(testPolicyContext, eps, nil, portrule, tuple, tuple.Protocol, nil, nil)
		c.Assert(err, Not(IsNil))
	}
}

type SortablePolicyRules []*models.PolicyRule

func (a SortablePolicyRules) Len() int           { return len(a) }
func (a SortablePolicyRules) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortablePolicyRules) Less(i, j int) bool { return a[i].Rule < a[j].Rule }

func (s *PolicyTestSuite) TestJSONMarshal(c *C) {
	model := &models.L4Policy{}
	c.Assert(pretty.Sprintf("%+ v", model.Egress), checker.DeepEquals, "[]")
	c.Assert(pretty.Sprintf("%+ v", model.Ingress), checker.DeepEquals, "[]")

	policy := L4Policy{
		Egress: L4PolicyMap{
			"8080/TCP": {
				Port:     8080,
				Protocol: api.ProtoTCP,
				Ingress:  false,
			},
		},
		Ingress: L4PolicyMap{
			"80/TCP": {
				Port: 80, Protocol: api.ProtoTCP,
				L7Parser: "http",
				PerSelectorPolicies: L7DataMap{
					cachedFooSelector: &PerSelectorPolicy{
						L7Rules: api.L7Rules{
							HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
						},
					},
				},
				Ingress: true,
			},
			"9090/TCP": {
				Port: 9090, Protocol: api.ProtoTCP,
				L7Parser: "tester",
				PerSelectorPolicies: L7DataMap{
					cachedFooSelector: &PerSelectorPolicy{
						L7Rules: api.L7Rules{
							L7Proto: "tester",
							L7: []api.PortRuleL7{
								map[string]string{
									"method": "PUT",
									"path":   "/"},
								map[string]string{
									"method": "GET",
									"path":   "/"},
							},
						},
					},
				},
				Ingress: true,
			},
			"8080/TCP": {
				Port: 8080, Protocol: api.ProtoTCP,
				L7Parser: "http",
				PerSelectorPolicies: L7DataMap{
					cachedFooSelector: &PerSelectorPolicy{
						L7Rules: api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Path: "/", Method: "GET"},
								{Path: "/bar", Method: "GET"},
							},
						},
					},
					wildcardCachedSelector: &PerSelectorPolicy{
						L7Rules: api.L7Rules{
							HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
						},
					},
				},
				Ingress: true,
			},
		},
	}

	policy.Attach(testPolicyContext)
	model = policy.GetModel()
	c.Assert(model, NotNil)

	expectedEgress := []string{`{
  "port": 8080,
  "protocol": "TCP"
}`}
	sort.StringSlice(expectedEgress).Sort()
	sort.Sort(SortablePolicyRules(model.Egress))
	c.Assert(len(expectedEgress), Equals, len(model.Egress))
	for i := range expectedEgress {
		expected := new(bytes.Buffer)
		err := json.Compact(expected, []byte(expectedEgress[i]))
		c.Assert(err, Equals, nil, Commentf("Could not compact expected json"))
		c.Assert(model.Egress[i].Rule, Equals, expected.String())
	}

	expectedIngress := []string{`{
  "port": 80,
  "protocol": "TCP",
  "l7-rules": [
    {
      "\u0026LabelSelector{MatchLabels:map[string]string{any.foo: ,},MatchExpressions:[]LabelSelectorRequirement{},}": {
        "http": [
          {
            "path": "/",
            "method": "GET"
          }
        ]
      }
    }
  ]
}`,
		`{
  "port": 9090,
  "protocol": "TCP",
  "l7-rules": [
    {
      "\u0026LabelSelector{MatchLabels:map[string]string{any.foo: ,},MatchExpressions:[]LabelSelectorRequirement{},}": {
        "l7proto": "tester",
        "l7": [
          {
            "method": "PUT",
            "path": "/"
          },
          {
            "method": "GET",
            "path": "/"
          }
        ]
      }
    }
  ]
}`,
		`{
  "port": 8080,
  "protocol": "TCP",
  "l7-rules": [
    {
      "\u0026LabelSelector{MatchLabels:map[string]string{any.foo: ,},MatchExpressions:[]LabelSelectorRequirement{},}": {
        "http": [
          {
            "path": "/",
            "method": "GET"
          },
          {
            "path": "/bar",
            "method": "GET"
          }
        ]
      }
    },
    {
      "\u0026LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[]LabelSelectorRequirement{},}": {
        "http": [
          {
            "path": "/",
            "method": "GET"
          }
        ]
      }
    }
  ]
}`}
	sort.StringSlice(expectedIngress).Sort()
	sort.Sort(SortablePolicyRules(model.Ingress))
	c.Assert(len(expectedIngress), Equals, len(model.Ingress))
	for i := range expectedIngress {
		expected := new(bytes.Buffer)
		err := json.Compact(expected, []byte(expectedIngress[i]))
		c.Assert(err, Equals, nil, Commentf("Could not compact expected json"))
		c.Assert(model.Ingress[i].Rule, Equals, expected.String())
	}

	c.Assert(policy.HasEnvoyRedirect(), Equals, true)
	c.Assert(policy.HasProxylibRedirect(), Equals, true)
}
