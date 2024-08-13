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

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
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
	// Suppress the expected warning logs for this test
	oldLevel := logging.DefaultLogger.GetLevel()
	logging.DefaultLogger.SetLevel(logrus.ErrorLevel)
	defer logging.DefaultLogger.SetLevel(oldLevel)

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
	require.EqualValues(t, "[]", fmt.Sprintf("%+v", model.Egress))
	require.EqualValues(t, "[]", fmt.Sprintf("%+v", model.Ingress))

	policy := L4Policy{
		Egress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
			"8080/TCP": {
				Port:     8080,
				Protocol: api.ProtoTCP,
				Ingress:  false,
			},
		})},
		Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
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
		})},
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

// TestL4PolicyMapPortRangeOverlaps tests the Upsert, ExactLookup,
// and Delete methods with L4Filters that have overlapping ports.
func TestL4PolicyMapPortRangeOverlaps(t *testing.T) {
	portRanges := []struct {
		startPort, endPort uint16
	}{
		{1, 65534}, {1, 1023}, {0, 65535}, {1024, 65535},
	}
	for i, portRange := range portRanges {
		t.Run(fmt.Sprintf("%d-%d", portRange.startPort, portRange.endPort), func(tt *testing.T) {
			l4Map := NewL4PolicyMap()
			startFilter := &L4Filter{
				U8Proto:  u8proto.TCP,
				Protocol: api.ProtoTCP,
				Port:     portRange.startPort,
				EndPort:  portRange.endPort,
			}
			startPort := fmt.Sprintf("%d", portRange.startPort)
			l4Map.Upsert(startPort, portRange.endPort, "TCP", startFilter)
			// we need to make a copy of portRanges to splice.
			pRs := make([]struct{ startPort, endPort uint16 }, len(portRanges))
			copy(pRs, portRanges)
			// Iterate over every port range except the one being tested.
			for _, altPR := range append(pRs[:i], pRs[i+1:]...) {
				t.Logf("Checking for port range %d-%d on main port range %d-%d", altPR.startPort, altPR.endPort, portRange.startPort, portRange.endPort)
				altStartPort := fmt.Sprintf("%d", altPR.startPort)
				// This range should not exist yet.
				altL4 := l4Map.ExactLookup(altStartPort, altPR.endPort, "TCP")
				if altL4 != nil {
					require.Nilf(t, altL4, "%d-%d range found and it should not have been as %d-%d", altPR.startPort, altPR.endPort, altL4.Port, altL4.EndPort)
				}
				require.Nil(t, altL4)
				altFilter := &L4Filter{
					U8Proto:  u8proto.TCP,
					Protocol: api.ProtoTCP,
					Port:     altPR.startPort,
					EndPort:  altPR.endPort,
				}
				// Upsert overlapping port range.
				l4Map.Upsert(altStartPort, altPR.endPort, "TCP", altFilter)
				altL4 = l4Map.ExactLookup(altStartPort, altPR.endPort, "TCP")
				require.NotNilf(t, altL4, "%d-%d range not found and it should have been", altPR.startPort, altPR.endPort)
				require.True(t, altL4.Equals(nil, altFilter), "%d-%d range lookup returned a range of %d-%d",
					altPR.startPort, altPR.endPort, altL4.Port, altL4.EndPort)

				gotMainFilter := l4Map.ExactLookup(startPort, portRange.endPort, "TCP")
				require.Truef(t, gotMainFilter.Equals(nil, startFilter), "main range look up failed after %d-%d range upsert", altPR.startPort, altPR.endPort)

				// Delete overlapping port range, and make sure it's not there.
				l4Map.Delete(altStartPort, altPR.endPort, "TCP")
				altL4 = l4Map.ExactLookup(altStartPort, altPR.endPort, "TCP")
				if altL4 != nil {
					require.Nilf(t, altL4, "%d-%d range found after a delete and it should not have been as %d-%d", altPR.startPort, altPR.endPort, altL4.Port, altL4.EndPort)
				}
				require.Nil(t, altL4)

				gotMainFilter = l4Map.ExactLookup(startPort, portRange.endPort, "TCP")
				require.Truef(t, gotMainFilter.Equals(nil, startFilter), "main range look up failed after %d-%d range delete", altPR.startPort, altPR.endPort)

				// Put it back for the next iteration.
				l4Map.Upsert(altStartPort, altPR.endPort, "TCP", altFilter)
			}
		})
	}
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
