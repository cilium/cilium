// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

func perSelectorPolicyToString(psp *PerSelectorPolicy) string {
	b, err := json.Marshal(psp)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func TestRedirectType(t *testing.T) {
	require.Equal(t, redirectTypeNone, redirectTypes(0))
	require.Equal(t, redirectTypeDNS, redirectTypes(0x1))
	require.Equal(t, redirectTypeEnvoy, redirectTypes(0x2))
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
		{L7ParserType("foo"), L7ParserType("foo"), L7ParserType("foo"), true},
		{ParserTypeTLS, ParserTypeTLS, ParserTypeTLS, true},

		// None can be promoted to any other type
		{ParserTypeNone, ParserTypeDNS, ParserTypeDNS, true},
		{ParserTypeDNS, ParserTypeNone, ParserTypeDNS, true},

		{ParserTypeNone, ParserTypeHTTP, ParserTypeHTTP, true},
		{ParserTypeHTTP, ParserTypeNone, ParserTypeHTTP, true},

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

		{L7ParserType("foo"), ParserTypeCRD, ParserTypeNone, false},
		{ParserTypeCRD, L7ParserType("foo"), ParserTypeNone, false},

		// TLS can also be promoted to any other type except for DNS (but not demoted to
		// None)

		{ParserTypeTLS, ParserTypeHTTP, ParserTypeHTTP, true},
		{ParserTypeHTTP, ParserTypeTLS, ParserTypeHTTP, true},

		{ParserTypeTLS, L7ParserType("foo"), L7ParserType("foo"), true},
		{L7ParserType("foo"), ParserTypeTLS, L7ParserType("foo"), true},

		// DNS does not merge with anything else

		{ParserTypeCRD, ParserTypeDNS, ParserTypeNone, false},
		{ParserTypeDNS, ParserTypeCRD, ParserTypeNone, false},

		{ParserTypeTLS, ParserTypeDNS, ParserTypeNone, false},
		{ParserTypeDNS, ParserTypeTLS, ParserTypeNone, false},

		{ParserTypeDNS, ParserTypeHTTP, ParserTypeNone, false},
		{ParserTypeHTTP, ParserTypeDNS, ParserTypeNone, false},

		{ParserTypeDNS, L7ParserType("foo"), ParserTypeNone, false},
		{L7ParserType("foo"), ParserTypeDNS, ParserTypeNone, false},

		// Different L7 parsers do not merge with each other nor with HTTP

		{L7ParserType("bar"), L7ParserType("foo"), ParserTypeNone, false},
		{L7ParserType("foo"), L7ParserType("bar"), ParserTypeNone, false},

		{L7ParserType("bar"), ParserTypeHTTP, ParserTypeNone, false},
		{ParserTypeHTTP, L7ParserType("bar"), ParserTypeNone, false},
	} {
		res, err := tt.a.Merge(tt.b)
		if tt.success {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
		if res != tt.c {
			t.Logf("Merge %s with %s, expecting %s\n", tt.a, tt.b, tt.c)
		}
		require.Equal(t, tt.c, res)
	}
}

func TestCreateL4Filter(t *testing.T) {
	// disable allow local host to simplify the this test
	oldLocalhostOpt := option.Config.UnsafeDaemonConfigOption.AllowLocalhost
	option.Config.UnsafeDaemonConfigOption.AllowLocalhost = option.AllowLocalhostPolicy
	defer func() { option.Config.UnsafeDaemonConfigOption.AllowLocalhost = oldLocalhostOpt }()

	td := newTestData(t, hivetest.Logger(t))
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

	for _, es := range selectors {
		eps := types.ToSelectors(es)
		entry := &types.PolicyEntry{
			Verdict: types.Allow,
			L3:      eps,
			Ingress: true,
			L4:      []api.PortRule{*portrule},
		}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		filter, err := createL4Filter(td.testPolicyContext, entry, portrule, tuple)
		require.NoError(t, err)
		require.Len(t, filter.PerSelectorPolicies, 1)
		for _, sp := range filter.PerSelectorPolicies {
			explicit, authType := getAuthType(sp.Authentication)
			require.False(t, explicit)
			require.Equal(t, AuthTypeDisabled, authType)
			require.Equal(t, redirectTypeEnvoy, sp.redirectType())
		}

		entry.Ingress = false
		filter, err = createL4Filter(td.testPolicyContext, entry, portrule, tuple)
		require.NoError(t, err)
		require.Len(t, filter.PerSelectorPolicies, 1)
		for _, sp := range filter.PerSelectorPolicies {
			explicit, authType := getAuthType(sp.Authentication)
			require.False(t, explicit)
			require.Equal(t, AuthTypeDisabled, authType)
			require.Equal(t, redirectTypeEnvoy, sp.redirectType())
		}
	}
}

func TestCreateL4FilterAuthRequired(t *testing.T) {
	// disable allow local host to simplify the this test
	oldLocalhostOpt := option.Config.UnsafeDaemonConfigOption.AllowLocalhost
	option.Config.UnsafeDaemonConfigOption.AllowLocalhost = option.AllowLocalhostPolicy
	defer func() { option.Config.UnsafeDaemonConfigOption.AllowLocalhost = oldLocalhostOpt }()

	td := newTestData(t, hivetest.Logger(t))
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

	for _, es := range selectors {
		eps := types.ToSelectors(es)
		entry := &types.PolicyEntry{
			Verdict:        types.Allow,
			L3:             eps,
			Ingress:        true,
			L4:             []api.PortRule{*portrule},
			Authentication: &api.Authentication{Mode: api.AuthenticationModeDisabled},
		}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		filter, err := createL4Filter(td.testPolicyContext, entry, portrule, tuple)
		require.NoError(t, err)
		require.Len(t, filter.PerSelectorPolicies, 1)
		for _, sp := range filter.PerSelectorPolicies {
			explicit, authType := getAuthType(sp.Authentication)
			require.True(t, explicit)
			require.Equal(t, AuthTypeDisabled, authType)
			require.Equal(t, redirectTypeEnvoy, sp.redirectType())
		}

		entry.Ingress = false
		filter, err = createL4Filter(td.testPolicyContext, entry, portrule, tuple)
		require.NoError(t, err)
		require.Len(t, filter.PerSelectorPolicies, 1)
		for _, sp := range filter.PerSelectorPolicies {
			explicit, authType := getAuthType(sp.Authentication)
			require.True(t, explicit)
			require.Equal(t, AuthTypeDisabled, authType)
			require.Equal(t, redirectTypeEnvoy, sp.redirectType())
		}
	}
}

func TestCreateL4FilterMissingSecret(t *testing.T) {
	// Suppress the expected warning logs for this test

	td := newTestData(t, hivetest.Logger(t))
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

	for _, es := range selectors {
		eps := types.ToSelectors(es)
		entry := &types.PolicyEntry{
			L3:      eps,
			Ingress: true,
			L4:      []api.PortRule{*portrule},
		}
		// Regardless of ingress/egress, we should end up with
		// a single L7 rule whether the selector is wildcarded
		// or if it is based on specific labels.
		_, err := createL4Filter(td.testPolicyContext, entry, portrule, tuple)
		require.Error(t, err)

		entry.Ingress = false
		_, err = createL4Filter(td.testPolicyContext, entry, portrule, tuple)
		require.Error(t, err)
	}
}

type SortablePolicyRules []*models.PolicyRule

func (a SortablePolicyRules) Len() int           { return len(a) }
func (a SortablePolicyRules) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortablePolicyRules) Less(i, j int) bool { return a[i].Rule < a[j].Rule }

func TestJSONMarshal(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))
	model := &models.L4Policy{}
	require.Equal(t, "[]", fmt.Sprintf("%+v", model.Egress))
	require.Equal(t, "[]", fmt.Sprintf("%+v", model.Ingress))

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
				PerSelectorPolicies: L7DataMap{
					td.cachedFooSelector: &PerSelectorPolicy{
						Verdict:  types.Allow,
						L7Parser: ParserTypeHTTP,
						L7Rules: api.L7Rules{
							HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
						},
					},
				},
				Ingress: true,
			},
			"9090/TCP": {
				Port: 9090, Protocol: api.ProtoTCP,
				PerSelectorPolicies: L7DataMap{
					td.cachedFooSelector: &PerSelectorPolicy{
						Verdict:  types.Allow,
						L7Parser: "tester",
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
				PerSelectorPolicies: L7DataMap{
					td.cachedFooSelector: &PerSelectorPolicy{
						Verdict:  types.Allow,
						L7Parser: ParserTypeHTTP,
						L7Rules: api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Path: "/", Method: "GET"},
								{Path: "/bar", Method: "GET"},
							},
						},
					},
					td.wildcardCachedSelector: &PerSelectorPolicy{
						Verdict: types.Allow,
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
	require.Len(t, model.Egress, len(expectedEgress))
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
      "\u0026LabelSelector{MatchLabels:map[string]string{any:foo: ,},MatchExpressions:[]LabelSelectorRequirement{},}": {
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
      "\u0026LabelSelector{MatchLabels:map[string]string{any:foo: ,},MatchExpressions:[]LabelSelectorRequirement{},}": {
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
      "\u0026LabelSelector{MatchLabels:map[string]string{any:foo: ,},MatchExpressions:[]LabelSelectorRequirement{},}": {
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
	require.Len(t, model.Ingress, len(expectedIngress))
	for i := range expectedIngress {
		expected := new(bytes.Buffer)
		err := json.Compact(expected, []byte(expectedIngress[i]))
		require.NoError(t, err, "Could not compact expected json")
		require.Equal(t, expected.String(), model.Ingress[i].Rule)
	}

	require.True(t, policy.HasEnvoyRedirect())
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
			l4Map := makeL4PolicyMap()
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
			for _, altPR := range slices.Delete(pRs, i, i+1) {
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
				require.True(t, altL4.Equals(altFilter), "%d-%d range lookup returned a range of %d-%d",
					altPR.startPort, altPR.endPort, altL4.Port, altL4.EndPort)

				gotMainFilter := l4Map.ExactLookup(startPort, portRange.endPort, "TCP")
				require.Truef(t, gotMainFilter.Equals(startFilter), "main range look up failed after %d-%d range upsert", altPR.startPort, altPR.endPort)

				// Delete overlapping port range, and make sure it's not there.
				l4Map.Delete(altStartPort, altPR.endPort, "TCP")
				altL4 = l4Map.ExactLookup(altStartPort, altPR.endPort, "TCP")
				if altL4 != nil {
					require.Nilf(t, altL4, "%d-%d range found after a delete and it should not have been as %d-%d", altPR.startPort, altPR.endPort, altL4.Port, altL4.EndPort)
				}
				require.Nil(t, altL4)

				gotMainFilter = l4Map.ExactLookup(startPort, portRange.endPort, "TCP")
				require.Truef(t, gotMainFilter.Equals(startFilter), "main range look up failed after %d-%d range delete", altPR.startPort, altPR.endPort)

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
	for range 1000 {
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

func BenchmarkEvaluateL4PolicyMapState(b *testing.B) {
	logger := hivetest.Logger(b)
	owner := DummyOwner{logger: logger}

	newEmptyEndpointPolicy := func() *EndpointPolicy {
		return &EndpointPolicy{
			SelectorPolicy:   &selectorPolicy{},
			PolicyOwner:      owner,
			policyMapState:   emptyMapState(logger),
			policyMapChanges: MapChanges{logger: logger},
		}
	}

	ws := newTestCachedSelector("wildcard", true)
	testSelA := newTestCachedSelector("test-selector-a", false, 101, 102, 103)
	testSelB := newTestCachedSelector("test-selector-b", false, 201, 202, 203)
	testSelC := newTestCachedSelector("test-selector-c", false, 301, 302, 303)

	testL4Filters := []*L4Filter{
		// L4 wildcard selector.
		{
			Port:     9000,
			Protocol: api.ProtoTCP,
			wildcard: ws,
			PerSelectorPolicies: L7DataMap{
				ws: nil,
			},
			Ingress: true,
		},
		// L4 with multiple selectors.
		{
			Port:     9001,
			Protocol: api.ProtoTCP,
			PerSelectorPolicies: L7DataMap{
				testSelA: nil,
				testSelB: nil,
				testSelC: nil,
			},
			Ingress: true,
		},
		// L4 with multiple selectors and wildcard.
		{
			Port:     9002,
			Protocol: api.ProtoTCP,
			wildcard: ws,
			PerSelectorPolicies: L7DataMap{
				ws:       nil,
				testSelA: nil,
				testSelB: nil,
				testSelC: nil,
			},
			Ingress: true,
		},
	}

	b.ReportAllocs()

	b.Run("ToMapState", func(b *testing.B) {
		for b.Loop() {
			b.StopTimer()
			epPolicy := newEmptyEndpointPolicy()
			b.StartTimer()

			for _, filter := range testL4Filters {
				filter.toMapState(logger, types.HighestPriority, types.LowestPriority, epPolicy, 0, ChangeState{})
			}
		}
	})

	b.Run("IncrementalToMapState", func(b *testing.B) {
		for b.Loop() {
			b.StopTimer()
			epPolicy := newEmptyEndpointPolicy()
			l4Policy := L4Policy{
				users: map[*EndpointPolicy]struct{}{
					epPolicy: {},
				},
			}

			// Compute initial policy with just the wildcard selectors.
			for _, filter := range testL4Filters {
				if filter.wildcard != nil {
					psp := filter.PerSelectorPolicies
					filter.PerSelectorPolicies = L7DataMap{ws: nil}

					filter.toMapState(logger, types.HighestPriority, types.LowestPriority, epPolicy, 0, ChangeState{})
					filter.PerSelectorPolicies = psp
				}
			}
			b.StartTimer()

			for _, filter := range testL4Filters {
				for cs := range filter.PerSelectorPolicies {
					testSel, ok := cs.(*testCachedSelector)
					if !ok {
						b.FailNow()
					}

					l4Policy.AccumulateMapChanges(logger, filter, cs, testSel.selections, nil)
					l4Policy.SyncMapChanges(filter, types.MockSelectorSnapshot())

					closer, _ := epPolicy.ConsumeMapChanges()
					closer()
				}
			}
		}
	})
}

// TestHoldCountPerEndpoint validates that per-endpoint holdCount prevents
// premature policy detachment.
//
// Scenario: Two endpoints (A and B) share the same identity and will adopt the
// same policy. An existing user (C) is currently using the policy.
func TestHoldCountPerEndpoint(t *testing.T) {
	l4policy := NewL4Policy(1)
	sc := testNewSelectorCache(t, nil, identity.IdentityMap{})

	// Existing user C
	existingUser := &EndpointPolicy{
		PolicyOwner: &dummyEndpoint{ID: 100},
	}
	l4policy.users[existingUser] = struct{}{}

	// Per-endpoint approach: each endpoint calls addHold when it gets the policy
	require.True(t, l4policy.addHold()) // Endpoint A gets policy
	require.True(t, l4policy.addHold()) // Endpoint B gets policy
	require.Equal(t, 2, l4policy.holdCount)

	endpointA := &EndpointPolicy{
		PolicyOwner: &dummyEndpoint{ID: 2},
	}
	endpointB := &EndpointPolicy{
		PolicyOwner: &dummyEndpoint{ID: 3},
	}

	// Endpoint A calls insertUser
	l4policy.insertUser(endpointA, sc)
	require.Equal(t, 1, l4policy.holdCount, "one hold remains for B")
	require.Len(t, l4policy.users, 2, "should have C and A")

	// Existing user C leaves
	l4policy.removeUser(existingUser, sc)
	// Does NOT detach because holdCount > 0
	require.NotNil(t, l4policy.users, "not detached, hold for B outstanding")
	require.Len(t, l4policy.users, 1, "only A remains")

	// Endpoint A leaves
	l4policy.removeUser(endpointA, sc)
	// Still does NOT detach because holdCount > 0
	require.NotNil(t, l4policy.users, "not detached, hold for B still outstanding")
	require.Empty(t, l4policy.users, "no users but hold prevents detachment")

	// Endpoint B calls insertUser - succeeds!
	l4policy.insertUser(endpointB, sc)

	// Success: B registered and released its hold
	require.Equal(t, 0, l4policy.holdCount, "all holds released")
	require.NotNil(t, l4policy.users, "policy not detached")
	require.Len(t, l4policy.users, 1, "B successfully registered")

	// Finally, B leaves — policy becomes idle (not detached)
	l4policy.removeUser(endpointB, sc)
	require.NotNil(t, l4policy.users, "policy idle — not superseded, users map preserved")
	require.Empty(t, l4policy.users, "no users remain")

	// Simulate supersession, then verify detach works
	l4policy.superseded = true
	l4policy.maybeDetachLocked(sc)
	require.Nil(t, l4policy.users, "policy detached after being superseded")
}

// TestHoldCountRealCodePath tests the holdCount mechanism using real code paths
// through updateSelectorPolicy() and DistillPolicy() instead of manually calling
// addHold() and insertUser().
//
// This simulates the real scenario where:
// 1. Policy is computed once per identity via updateSelectorPolicy()
// 2. Multiple endpoints sharing that identity each call DistillPolicy()
func TestHoldCountRealCodePath(t *testing.T) {
	// Set up real repository and cache
	repo := NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	repo.revision.Store(1)
	cache := repo.policyCache

	// Create a test identity
	ep1 := testutils.NewTestEndpoint(t)
	identity1 := ep1.GetSecurityIdentity()

	// Insert identity into cache
	cache.insert(identity1)

	// Simulate policy computation - with the fix, this no longer adds holds
	policy, _, _, err := cache.updateSelectorPolicy(identity1, ep1.Id)
	require.NoError(t, err)
	require.NotNil(t, policy)

	// Check initial holdCount - should be 0 after updateSelectorPolicy
	require.Equal(t, 0, policy.L4Policy.holdCount, "policy should have no holds after updateSelectorPolicy")

	// Create an existing user on the policy
	// Each endpoint gets its own distinct PolicyOwner with separate state
	logger := hivetest.Logger(t)
	existingOwner := newTestPolicyOwner(100, logger)

	// Simulate endpoint getting policy and adding hold (what endpoint code does)
	held := policy.AddHold()
	require.True(t, held, "AddHold should succeed on live policy")
	require.Equal(t, 1, policy.L4Policy.holdCount, "hold should be added")

	existingPolicy := policy.DistillPolicy(logger, existingOwner, nil)

	// After DistillPolicy, insertUser is called, which releases the hold
	require.Equal(t, 0, policy.L4Policy.holdCount, "hold should be released after DistillPolicy")
	require.Len(t, policy.L4Policy.users, 1, "should have 1 user")

	// Simulate two more endpoints (A and B) reading the same policy from statedb
	// In real code, they would both call DistillPolicy() but at different times
	// Each has its own ID and MapState to properly represent distinct endpoints
	ownerA := newTestPolicyOwner(200, logger)
	ownerB := newTestPolicyOwner(300, logger)

	// Both endpoints add holds when they get the policy
	require.True(t, policy.AddHold()) // Endpoint A
	require.True(t, policy.AddHold()) // Endpoint B
	require.Equal(t, 2, policy.L4Policy.holdCount, "should have 2 holds for A and B")

	// Endpoint A calls DistillPolicy (which calls insertUser and releases one hold)
	policyA := policy.DistillPolicy(logger, ownerA, nil)
	require.NotNil(t, policyA)
	require.Equal(t, 1, policy.L4Policy.holdCount, "one hold should remain for B")
	require.Len(t, policy.L4Policy.users, 2, "should have existing user + A")

	// Verify each endpoint has its own distinct state
	require.NotSame(t, existingPolicy, policyA, "each endpoint should have its own EndpointPolicy")
	require.NotSame(t, existingOwner.PreviousMapState(), ownerA.PreviousMapState(), "each endpoint should have its own MapState")

	// Existing user leaves
	policy.removeUser(existingPolicy)
	require.Equal(t, 1, policy.L4Policy.holdCount, "B's hold still outstanding")
	require.Len(t, policy.L4Policy.users, 1, "should have only A")

	// Endpoint A leaves (e.g., regenerates with new policy)
	policy.removeUser(policyA)

	// With the fix: Policy does NOT detach because holdCount > 0 (B's hold)
	// Without the fix: Policy would detach here (holdCount==0 && len(users)==0)
	require.Equal(t, 1, policy.L4Policy.holdCount, "B's hold prevents detachment")
	require.NotNil(t, policy.L4Policy.users, "policy should not be detached due to outstanding hold")
	require.Empty(t, policy.L4Policy.users, "no users remain but policy not detached")

	// Endpoint B (which got the policy reference earlier) now tries to DistillPolicy
	policyB := policy.DistillPolicy(logger, ownerB, nil)
	require.NotNil(t, policyB)
	require.NotSame(t, policyB, policyA, "B should have its own EndpointPolicy")
	require.NotSame(t, ownerB.PreviousMapState(), ownerA.PreviousMapState(), "B should have its own MapState")

	// Success: Endpoint B registered successfully because policy wasn't detached
	require.Equal(t, 0, policy.L4Policy.holdCount, "B's hold released after DistillPolicy")
	require.NotNil(t, policy.L4Policy.users, "policy should not be detached")
	require.Len(t, policy.L4Policy.users, 1, "B should have registered successfully")
}

// TestAddHoldRejectsDetachedPolicy reproduces the exact race condition that
// causes the regen loop: compute creates policy P, a second compute replaces P
// with Q, MaybeDetach(P) detaches P, then an endpoint tries to use the stale P.
//
// Without fix: AddHold returns true on detached P → DistillPolicy fires
// RegenerateIfAlive → regen loop.
// With fix: AddHold returns false on detached P → endpoint aborts → no loop.
func TestAddHoldRejectsDetachedPolicy(t *testing.T) {
	// Real repo and cache
	repo := NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	repo.revision.Store(1)
	cache := repo.policyCache
	logger := hivetest.Logger(t)

	ep := testutils.NewTestEndpoint(t)
	identity := ep.GetSecurityIdentity()
	cache.insert(identity)

	// --- Simulate first compute: creates P at rev=1 ---
	repo.mutex.RLock()
	P, _, _, err := cache.updateSelectorPolicy(identity, 0)
	repo.mutex.RUnlock()
	require.NoError(t, err)
	require.NotNil(t, P.L4Policy.users, "P should be live")

	// --- Simulate second compute: creates Q at rev=2, old=P ---
	repo.BumpRevision()
	repo.mutex.RLock()
	Q, old, _, err := cache.updateSelectorPolicy(identity, 0)
	repo.mutex.RUnlock()
	require.NoError(t, err)
	require.Same(t, P, old)
	require.NotSame(t, P, Q)

	// --- Simulate compute.go: MaybeDetach old policy after commit ---
	old.MaybeDetach()
	require.Nil(t, P.L4Policy.users, "P should be detached")

	// --- Simulate endpoint trying to use stale P (the race) ---
	// This mirrors the real endpoint control flow in regeneratePolicy():
	//   held := selectorPolicy.AddHold()
	//   if held { DistillPolicy(owner) }
	regenOwner := newRegenTrackingOwner(100, logger)
	held := P.AddHold()
	if held {
		P.DistillPolicy(logger, regenOwner, nil)
	}

	// The fix: AddHold rejects detached policy, so DistillPolicy is never called,
	// and RegenerateIfAlive never fires.
	//
	// Without fix: held=true → DistillPolicy called → insertUser sees users==nil
	//   → fires RegenerateIfAlive → regenCount > 0 → BOTH assertions FAIL
	// With fix: held=false → DistillPolicy skipped → regenCount == 0 → PASSES
	require.False(t, held, "AddHold must reject detached policy")
	// Ensure any async RegenerateIfAlive goroutine has had time to complete
	require.Never(t, func() bool {
		return regenOwner.regenCount.Load() > 0
	}, 200*time.Millisecond, 10*time.Millisecond,
		"RegenerateIfAlive must not fire — the regen loop is prevented")

	// --- Live policy Q still works normally ---
	held = Q.AddHold()
	require.True(t, held, "AddHold must accept live policy")

	safeOwner := newRegenTrackingOwner(200, logger)
	epPolicy := Q.DistillPolicy(logger, safeOwner, nil)
	require.NotNil(t, epPolicy)
	require.Len(t, Q.L4Policy.users, 1, "endpoint registered on Q")
	require.Equal(t, int32(0), safeOwner.regenCount.Load(),
		"no spurious regen when using live policy")
}

// dummyEndpoint is a minimal PolicyOwner implementation for unit tests.
type dummyEndpoint struct {
	ID uint64
}

func (d *dummyEndpoint) GetID() uint64 { return d.ID }
func (d *dummyEndpoint) GetNamedPort(ingress bool, name string, proto u8proto.U8proto, _ iter.Seq[identity.NumericIdentity]) uint16 {
	return 0
}
func (d *dummyEndpoint) PolicyDebug(msg string, attrs ...any) {}
func (d *dummyEndpoint) IsHost() bool                         { return false }
func (d *dummyEndpoint) PreviousMapState() *MapState          { return &MapState{} }
func (d *dummyEndpoint) RegenerateIfAlive(meta *regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool, 1)
	ch <- false
	close(ch)
	return ch
}

// testPolicyOwner provides a PolicyOwner implementation for tests that need
// per-endpoint state (logger, previousState).
type testPolicyOwner struct {
	id            uint64
	previousState *MapState
	logger        *slog.Logger
}

func newTestPolicyOwner(id uint64, logger *slog.Logger) *testPolicyOwner {
	return &testPolicyOwner{
		id:            id,
		previousState: &MapState{},
		logger:        logger,
	}
}

func (t *testPolicyOwner) GetID() uint64 { return t.id }

func (t *testPolicyOwner) GetNamedPort(ingress bool, name string, proto u8proto.U8proto, _ iter.Seq[identity.NumericIdentity]) uint16 {
	return 0
}

func (t *testPolicyOwner) PolicyDebug(msg string, attrs ...any) {
	if t.logger != nil {
		t.logger.Debug(msg, attrs...)
	}
}

func (t *testPolicyOwner) IsHost() bool { return false }

func (t *testPolicyOwner) PreviousMapState() *MapState {
	return t.previousState
}

func (t *testPolicyOwner) RegenerateIfAlive(meta *regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool, 1)
	ch <- false
	close(ch)
	return ch
}

// regenTrackingOwner extends testPolicyOwner with an atomic regen counter
// to detect when RegenerateIfAlive is fired (the regen loop trigger).
type regenTrackingOwner struct {
	testPolicyOwner
	regenCount atomic.Int32
}

func newRegenTrackingOwner(id uint64, logger *slog.Logger) *regenTrackingOwner {
	return &regenTrackingOwner{
		testPolicyOwner: testPolicyOwner{
			id:            id,
			previousState: &MapState{},
			logger:        logger,
		},
	}
}

func (t *regenTrackingOwner) RegenerateIfAlive(meta *regeneration.ExternalRegenerationMetadata) <-chan bool {
	t.regenCount.Add(1)
	ch := make(chan bool, 1)
	ch <- false
	close(ch)
	return ch
}
