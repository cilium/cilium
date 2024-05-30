// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"testing"

	"github.com/kr/pretty"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestRedirectType(t *testing.T) {
	require.Equal(t, redirectTypes(0), redirectTypeNone)
	require.Equal(t, redirectTypes(0x1), redirectTypeDNS)
	require.Equal(t, redirectTypes(0x2), redirectTypeEnvoy)
	require.Equal(t, redirectTypes(0x4)|redirectTypeEnvoy, redirectTypeProxylib)
	require.Equal(t, redirectTypeEnvoy, redirectTypeProxylib&redirectTypeEnvoy)
}

func TestParserTypeMerge(t *testing.T) {
	for _, tt := range []struct {
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
		res, err := tt.a.Merge(tt.b)
		if tt.success {
			require.Equal(t, nil, err)
		} else {
			require.NotEqual(t, nil, err)
		}
		if res != tt.c {
			fmt.Printf("Merge %s with %s, expecting %s\n", tt.a, tt.b, tt.c)
		}
		require.Equal(t, tt.c, res)
	}
}

func TestCreateL4Filter(t *testing.T) {
	td := newTestData()
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
		filter, err := createL4IngressFilter(td.testPolicyContext, eps, nil, nil, portrule, tuple, tuple.Protocol, nil)
		require.NoError(t, err)
		require.Equal(t, 1, len(filter.PerSelectorPolicies))
		for _, r := range filter.PerSelectorPolicies {
			hasAuth, authType := r.GetAuthType()
			require.Equal(t, DefaultAuthType, hasAuth)
			require.Equal(t, AuthTypeDisabled, authType)
		}
		require.Equal(t, redirectTypeEnvoy, filter.redirectType())

		filter, err = createL4EgressFilter(td.testPolicyContext, eps, nil, portrule, tuple, tuple.Protocol, nil, nil)
		require.NoError(t, err)
		require.Equal(t, 1, len(filter.PerSelectorPolicies))
		for _, r := range filter.PerSelectorPolicies {
			hasAuth, authType := r.GetAuthType()
			require.Equal(t, DefaultAuthType, hasAuth)
			require.Equal(t, AuthTypeDisabled, authType)
		}
		require.Equal(t, redirectTypeEnvoy, filter.redirectType())
	}
}

func TestCreateL4FilterAuthRequired(t *testing.T) {
	td := newTestData()
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

	auth := &api.Authentication{Mode: api.AuthenticationModeDisabled}
	for _, selector := range selectors {
		eps := []api.EndpointSelector{selector}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		filter, err := createL4IngressFilter(td.testPolicyContext, eps, auth, nil, portrule, tuple, tuple.Protocol, nil)
		require.NoError(t, err)
		require.Equal(t, 1, len(filter.PerSelectorPolicies))
		for _, r := range filter.PerSelectorPolicies {
			hasAuth, authType := r.GetAuthType()
			require.Equal(t, ExplicitAuthType, hasAuth)
			require.Equal(t, AuthTypeDisabled, authType)
		}
		require.Equal(t, redirectTypeEnvoy, filter.redirectType())

		filter, err = createL4EgressFilter(td.testPolicyContext, eps, auth, portrule, tuple, tuple.Protocol, nil, nil)
		require.NoError(t, err)
		require.Equal(t, 1, len(filter.PerSelectorPolicies))
		for _, r := range filter.PerSelectorPolicies {
			hasAuth, authType := r.GetAuthType()
			require.Equal(t, ExplicitAuthType, hasAuth)
			require.Equal(t, AuthTypeDisabled, authType)
		}
		require.Equal(t, redirectTypeEnvoy, filter.redirectType())
	}
}

func TestCreateL4FilterMissingSecret(t *testing.T) {
	td := newTestData()
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
		_, err := createL4IngressFilter(td.testPolicyContext, eps, nil, nil, portrule, tuple, tuple.Protocol, nil)
		require.NotNil(t, err)

		_, err = createL4EgressFilter(td.testPolicyContext, eps, nil, portrule, tuple, tuple.Protocol, nil, nil)
		require.NotNil(t, err)
	}
}

type SortablePolicyRules []*models.PolicyRule

func (a SortablePolicyRules) Len() int           { return len(a) }
func (a SortablePolicyRules) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortablePolicyRules) Less(i, j int) bool { return a[i].Rule < a[j].Rule }

func TestJSONMarshal(t *testing.T) {
	td := newTestData()
	model := &models.L4Policy{}
	require.EqualValues(t, "[]", pretty.Sprintf("%+ v", model.Egress))
	require.EqualValues(t, "[]", pretty.Sprintf("%+ v", model.Ingress))

	policy := L4Policy{
		Egress: L4DirectionPolicy{PortRules: L4PolicyMap{
			"8080/TCP": {
				Port:     8080,
				Protocol: api.ProtoTCP,
				Ingress:  false,
			},
		}},
		Ingress: L4DirectionPolicy{PortRules: L4PolicyMap{
			"80/TCP": {
				Port: 80, Protocol: api.ProtoTCP,
				L7Parser: "http",
				PerSelectorPolicies: L7DataMap{
					td.cachedFooSelector: &PerSelectorPolicy{
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
					td.cachedFooSelector: &PerSelectorPolicy{
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
					td.cachedFooSelector: &PerSelectorPolicy{
						L7Rules: api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Path: "/", Method: "GET"},
								{Path: "/bar", Method: "GET"},
							},
						},
					},
					td.wildcardCachedSelector: &PerSelectorPolicy{
						L7Rules: api.L7Rules{
							HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
						},
					},
				},
				Ingress: true,
			},
		}},
	}

	policy.Attach(td.testPolicyContext)
	model = policy.GetModel()
	require.NotNil(t, model)

	expectedEgress := []string{`{
  "port": 8080,
  "protocol": "TCP"
}`}
	sort.StringSlice(expectedEgress).Sort()
	sort.Sort(SortablePolicyRules(model.Egress))
	require.Equal(t, len(model.Egress), len(expectedEgress))
	for i := range expectedEgress {
		expected := new(bytes.Buffer)
		err := json.Compact(expected, []byte(expectedEgress[i]))
		require.NoError(t, err, "Could not compact expected json")
		require.Equal(t, expected.String(), model.Egress[i].Rule)
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
	require.Equal(t, len(model.Ingress), len(expectedIngress))
	for i := range expectedIngress {
		expected := new(bytes.Buffer)
		err := json.Compact(expected, []byte(expectedIngress[i]))
		require.NoError(t, err, "Could not compact expected json")
		require.Equal(t, expected.String(), model.Ingress[i].Rule)
	}

	require.True(t, policy.HasEnvoyRedirect())
	require.True(t, policy.HasProxylibRedirect())
}

func BenchmarkContainsAllL3L4(b *testing.B) {
	id := uint16(rand.IntN(65535))
	port := uint16(rand.IntN(65535))

	b.ReportAllocs()
	for i := 0; i < 1000; i++ {
		b.StartTimer()
		proxyID := ProxyID(id, true, "TCP", port, "")
		if proxyID != strconv.FormatInt(int64(id), 10)+"ingress:TCP:8080:" {
			b.Failed()
		}
		_, _, _, _, _, err := ParseProxyID(proxyID)
		if err != nil {
			b.Failed()
		}
		b.StopTimer()
	}
}
