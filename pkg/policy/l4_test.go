// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"math/rand/v2"
	"sort"
	"strconv"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	pkgTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func perSelectorPolicyToString(psp *PerSelectorPolicy) string {
	b, err := json.Marshal(psp)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

type namedPortPolicyOwner struct {
	DummyOwner
	egressPorts map[identity.NumericIdentity]uint16
}

func (o namedPortPolicyOwner) egressPortFor(destID identity.NumericIdentity) uint16 {
	return o.egressPorts[destID]
}

func (o namedPortPolicyOwner) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 {
	return o.DummyOwner.GetIngressNamedPort(name, proto)
}

func (o namedPortPolicyOwner) GetEgressNamedPorts(name string, proto u8proto.U8proto, destIDs iter.Seq[identity.NumericIdentity]) pkgTypes.NidPortSeq {
	return func(yield func(identity.NumericIdentity, uint16) bool) {
		for destID := range destIDs {
			port := o.egressPortFor(destID)
			if port == 0 {
				continue
			}
			if !yield(destID, port) {
				return
			}
		}
	}
}

func TestEgressNamedPortToMapStateUnion(t *testing.T) {
	logger := hivetest.Logger(t)
	cs := newTestCachedSelector("backend", false, 101, 102, 103)
	owner := namedPortPolicyOwner{
		DummyOwner: DummyOwner{logger: logger},
		egressPorts: map[identity.NumericIdentity]uint16{
			101: 8080,
			102: 9090,
			103: 9090,
		},
	}
	epPolicy := &EndpointPolicy{
		PolicyOwner:    owner,
		policyMapState: newMapState(logger, nil, namedPortRules),
		selectors:      types.MockSelectorSnapshot(),
	}
	filter := &L4Filter{
		PortName: "http",
		Protocol: api.ProtoTCP,
		U8Proto:  u8proto.TCP,
		PerSelectorPolicies: L7DataMap{
			cs: nil,
		},
	}

	filter.toMapState(logger, types.HighestPriority, types.LowestPriority, epPolicy, namedPortRules, ChangeState{})

	for _, key := range []Key{
		EgressKey().WithIdentity(101).WithTCPPort(8080),
		EgressKey().WithIdentity(102).WithTCPPort(9090),
		EgressKey().WithIdentity(103).WithTCPPort(9090),
	} {
		_, ok := epPolicy.policyMapState.Get(key)
		require.True(t, ok, "missing key %s", key)
	}
	_, ok := epPolicy.policyMapState.Get(EgressKey().WithIdentity(102).WithTCPPort(8080))
	require.False(t, ok)
}

func TestEgressNamedPortWildcardOptimization(t *testing.T) {
	logger := hivetest.Logger(t)
	ws := newTestCachedSelector("wildcard", true, 101, 102)
	filter := &L4Filter{
		PortName: "http",
		Protocol: api.ProtoTCP,
		U8Proto:  u8proto.TCP,
		wildcard: ws,
		PerSelectorPolicies: L7DataMap{
			ws: nil,
		},
	}

	t.Run("egress does not use wildcard identity", func(t *testing.T) {
		owner := namedPortPolicyOwner{
			DummyOwner: DummyOwner{logger: logger},
			egressPorts: map[identity.NumericIdentity]uint16{
				101: 8080,
				102: 8080,
			},
		}
		epPolicy := &EndpointPolicy{
			PolicyOwner:    owner,
			policyMapState: newMapState(logger, nil, namedPortRules),
			selectors:      types.MockSelectorSnapshot(),
		}

		filter.toMapState(logger, types.HighestPriority, types.LowestPriority, epPolicy, namedPortRules, ChangeState{})

		_, ok := epPolicy.policyMapState.Get(EgressKey().WithIdentity(0).WithTCPPort(8080))
		require.False(t, ok)
		_, ok = epPolicy.policyMapState.Get(EgressKey().WithIdentity(101).WithTCPPort(8080))
		require.True(t, ok)
		_, ok = epPolicy.policyMapState.Get(EgressKey().WithIdentity(102).WithTCPPort(8080))
		require.True(t, ok)
	})

	t.Run("disagreed ports enumerate identities", func(t *testing.T) {
		owner := namedPortPolicyOwner{
			DummyOwner: DummyOwner{logger: logger},
			egressPorts: map[identity.NumericIdentity]uint16{
				101: 8080,
				102: 9090,
			},
		}
		epPolicy := &EndpointPolicy{
			PolicyOwner:    owner,
			policyMapState: newMapState(logger, nil, namedPortRules),
			selectors:      types.MockSelectorSnapshot(),
		}

		filter.toMapState(logger, types.HighestPriority, types.LowestPriority, epPolicy, namedPortRules, ChangeState{})

		for _, key := range []Key{
			EgressKey().WithIdentity(101).WithTCPPort(8080),
			EgressKey().WithIdentity(102).WithTCPPort(9090),
		} {
			_, ok := epPolicy.policyMapState.Get(key)
			require.True(t, ok, "missing key %s", key)
		}
		_, ok := epPolicy.policyMapState.Get(EgressKey().WithIdentity(0).WithTCPPort(8080))
		require.False(t, ok)
		_, ok = epPolicy.policyMapState.Get(EgressKey().WithIdentity(0).WithTCPPort(9090))
		require.False(t, ok)
	})
}

func TestNamedPortRulesDeleteByID(t *testing.T) {
	logger := hivetest.Logger(t)
	epPolicy := &EndpointPolicy{
		PolicyOwner:    DummyOwner{logger: logger},
		policyMapState: newMapState(logger, nil, namedPortRules),
	}
	require.NotNil(t, epPolicy.policyMapState.byId)

	entry := newMapStateEntry(0, types.HighestPriority, types.LowestPriority, NilRuleOrigin, 0, 0, types.Allow, NoAuthRequirement)
	for _, key := range []Key{
		EgressKey().WithIdentity(101).WithTCPPort(8080),
		EgressKey().WithIdentity(101).WithTCPPort(9090),
		EgressKey().WithIdentity(102).WithTCPPort(9090),
	} {
		epPolicy.policyMapState.insertWithChanges(types.HighestPriority.ToDenyPrecedence(), key, entry, namedPortRules, ChangeState{})
	}

	changes := MapChanges{logger: logger}
	changes.AccumulateMapDeletesByID(0, types.HighestPriority, []identity.NumericIdentity{101})
	changes.SyncMapChanges(types.MockSelectorSnapshot())
	_, changeState := changes.consumeMapChanges(epPolicy, namedPortRules)

	_, ok := epPolicy.policyMapState.Get(EgressKey().WithIdentity(101).WithTCPPort(8080))
	require.False(t, ok)
	_, ok = epPolicy.policyMapState.Get(EgressKey().WithIdentity(101).WithTCPPort(9090))
	require.False(t, ok)
	_, ok = epPolicy.policyMapState.Get(EgressKey().WithIdentity(102).WithTCPPort(9090))
	require.True(t, ok)
	require.Contains(t, changeState.Deletes, EgressKey().WithIdentity(101).WithTCPPort(8080))
	require.Contains(t, changeState.Deletes, EgressKey().WithIdentity(101).WithTCPPort(9090))
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

func TestPerSelectorPolicyGetPrecedence(t *testing.T) {
	var nilPolicy *PerSelectorPolicy

	for _, tc := range []struct {
		name     string
		policy   *PerSelectorPolicy
		expected types.Precedence
	}{
		{
			name:     "nil_defaults_to_max_allow",
			policy:   nilPolicy,
			expected: types.MaxAllowPrecedence,
		},
		{
			name: "allow_uses_allow_precedence",
			policy: &PerSelectorPolicy{
				Priority: 7,
			},
			expected: types.Priority(7).ToAllowPrecedence(),
		},
		{
			name: "deny_uses_deny_precedence",
			policy: &PerSelectorPolicy{
				Priority: 7,
				Verdict:  types.Deny,
			},
			expected: types.Priority(7).ToDenyPrecedence(),
		},
		{
			name: "pass_uses_pass_precedence",
			policy: &PerSelectorPolicy{
				Priority: 7,
				Verdict:  types.Pass,
			},
			expected: types.Priority(7).ToPassPrecedence(),
		},
		{
			name: "redirect_uses_listener_priority",
			policy: &PerSelectorPolicy{
				Priority:         7,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
			},
			expected: types.Priority(7).ToPrecedenceWithListenerPriority(false, true, ListenerPriorityHTTP),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.policy.GetPrecedence())
		})
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
				U8Proto:  u8proto.TCP,
				Ingress:  false,
			},
		})},
		Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
			"80/TCP": {
				Port: 80, Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
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
				Port: 9090, Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
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
			"8080/TCP": {
				Port: 8080, Protocol: api.ProtoTCP, U8Proto: u8proto.TCP,
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
