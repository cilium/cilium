// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/defaults"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	AuthTypeSpire      = types.AuthTypeSpire
	AuthTypeAlwaysFail = types.AuthTypeAlwaysFail
	AuthTypeDisabled   = types.AuthTypeDisabled
)

func setupTest(tb testing.TB) {
	ep1 = testutils.NewTestEndpoint(tb)
	ep2 = testutils.NewTestEndpoint(tb)
}

var (
	ep1, ep2 testutils.TestEndpoint
)

func localIdentity(n uint32) identity.NumericIdentity {
	return identity.NumericIdentity(n) | identity.IdentityScopeLocal
}

func TestCacheManagement(t *testing.T) {
	setupTest(t)
	repo := NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	cache := repo.policyCache
	identity := ep1.GetSecurityIdentity()
	require.Equal(t, identity, ep2.GetSecurityIdentity())

	// Nonsense delete of entry that isn't yet inserted
	deleted := cache.delete(identity)
	require.False(t, deleted)

	// Insert identity twice. Should be the same policy.
	policy1, updated, err := cache.updateSelectorPolicy(identity, ep1.Id)
	require.NoError(t, err)
	require.True(t, updated)
	policy2, updated, err := cache.updateSelectorPolicy(identity, ep1.Id)
	require.NoError(t, err)
	require.False(t, updated)
	// must be same pointer
	require.Same(t, policy2, policy1)

	// Despite two insert calls, there is no reference tracking; any delete
	// will clear the cache.
	cacheCleared := cache.delete(identity)
	require.True(t, cacheCleared)
	cacheCleared = cache.delete(identity)
	require.False(t, cacheCleared)

	// Insert two distinct identities, then delete one. Other should still
	// be there.
	ep3 := testutils.NewTestEndpoint(t)
	ep3.SetIdentity(1234, true)
	identity3 := ep3.GetSecurityIdentity()
	require.NotEqual(t, identity, identity3)
	policy1, _, _ = cache.updateSelectorPolicy(identity, ep1.Id)
	require.NotNil(t, policy1)
	policy3, _, _ := cache.updateSelectorPolicy(identity3, ep3.Id)
	require.NotNil(t, policy3)
	require.NotSame(t, policy3, policy1)
	_ = cache.delete(identity)
	_, updated, _ = cache.updateSelectorPolicy(identity3, ep3.Id)
	require.False(t, updated)
}

func TestCachePopulation(t *testing.T) {
	repo := NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	repo.revision.Store(42)
	cache := repo.policyCache

	identity1 := ep1.GetSecurityIdentity()
	require.Equal(t, identity1, ep2.GetSecurityIdentity())

	// Calculate the policy and observe that it's cached
	policy1, updated, err := cache.updateSelectorPolicy(identity1, ep1.Id)
	require.NoError(t, err)
	require.True(t, updated)
	_, updated, err = cache.updateSelectorPolicy(identity1, ep1.Id)
	require.NoError(t, err)
	require.False(t, updated)
	policy2, _, _ := cache.updateSelectorPolicy(identity1, ep1.Id)
	require.NotNil(t, policy2)
	require.Same(t, policy1, policy2)

	// Remove the identity and observe that it is no longer available
	cacheCleared := cache.delete(identity1)
	require.True(t, cacheCleared)
	_, updated, _ = cache.updateSelectorPolicy(identity1, ep1.Id)
	require.True(t, updated)

	// Attempt to update policy for non-cached endpoint and observe failure
	ep3 := testutils.NewTestEndpoint(t)
	ep3.SetIdentity(1234, true)
	policy3, updated, err := cache.updateSelectorPolicy(ep3.GetSecurityIdentity(), ep3.Id)
	require.NoError(t, err)
	require.True(t, updated)

	// policy3 must be different from ep1, ep2
	require.NoError(t, err)
	require.NotEqual(t, policy1, policy3)
}

// Distillery integration tests

var (
	// Identity, labels, selectors for an endpoint named "foo"
	identityFoo = identity.NumericIdentity(100)
	labelsFoo   = labels.ParseSelectLabelArray("foo", "blue")
	selectFoo_  = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	allowFooL3_ = selectFoo_
	denyFooL3__ = selectFoo_

	// Identity, labels, selectors for an endpoint named "bar"
	identityBar = identity.NumericIdentity(200)
	labelsBar   = labels.ParseSelectLabelArray("bar", "blue")
	selectBar_  = api.NewESFromLabels(labels.ParseSelectLabel("bar"))
	allowBarL3_ = selectBar_

	// API rule sections for composability
	// L4 rule sections
	allowAllL4_ []api.PortRule
	allowPort80 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
	}}
	allowNamedPort80 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "port-80", Protocol: api.ProtoTCP},
		},
	}}
	denyAllL4_ []api.PortDenyRule
	denyPort80 = []api.PortDenyRule{{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
	}}
	// L7 rule sections
	allowHTTPRoot = &api.L7Rules{
		HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: "/"},
		},
	}
	// API rule definitions for default-deny, L3, L3L4, L3L4L7, L4, L4L7
	lbls____NoAllow = labels.ParseLabelArray("no-allow")
	rule____NoAllow = api.NewRule().
			WithLabels(lbls____NoAllow).
			WithIngressRules([]api.IngressRule{{}})
	lblsL3____Allow = labels.ParseLabelArray("l3-allow")
	ruleL3____Allow = api.NewRule().
			WithLabels(lblsL3____Allow).
			WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowFooL3_},
			},
			ToPorts: allowAllL4_,
		}})
	lblsL3L4__Allow = labels.ParseLabelArray("l3l4-allow")
	ruleL3L4__Allow = api.NewRule().
			WithLabels(lblsL3L4__Allow).
			WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowFooL3_},
			},
			ToPorts: allowPort80,
		}})
	ruleL3npL4__Allow = api.NewRule().
				WithLabels(lblsL3L4__Allow).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowFooL3_},
			},
			ToPorts: allowNamedPort80,
		}})
	lblsL3L4L7Allow = labels.ParseLabelArray("l3l4l7-allow")
	ruleL3L4L7Allow = api.NewRule().
			WithLabels(lblsL3L4L7Allow).
			WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowFooL3_},
			},
			ToPorts: combineL4L7(allowPort80, allowHTTPRoot),
		}})
	ruleL3npL4L7Allow = api.NewRule().
				WithLabels(lblsL3L4L7Allow).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowFooL3_},
			},
			ToPorts: combineL4L7(allowNamedPort80, allowHTTPRoot),
		}})
	lbls__L4__Allow = labels.ParseLabelArray("l4-allow")
	rule__L4__Allow = api.NewRule().
			WithLabels(lbls__L4__Allow).
			WithIngressRules([]api.IngressRule{{
			ToPorts: allowPort80,
		}})
	rule__L4__AllowAuth = api.NewRule().
				WithLabels(lbls__L4__Allow).
				WithIngressRules([]api.IngressRule{{
			ToPorts: allowPort80,
			Authentication: &api.Authentication{
				Mode: api.AuthenticationModeRequired,
			},
		}})
	rule__npL4__Allow = api.NewRule().
				WithLabels(lbls__L4__Allow).
				WithIngressRules([]api.IngressRule{{
			ToPorts: allowNamedPort80,
		}})
	lbls__L4L7Allow = labels.ParseLabelArray("l4l7-allow")
	rule__L4L7Allow = api.NewRule().
			WithLabels(lbls__L4L7Allow).
			WithIngressRules([]api.IngressRule{{
			ToPorts: combineL4L7(allowPort80, allowHTTPRoot),
		}})
	rule__npL4L7Allow = api.NewRule().
				WithLabels(lbls__L4L7Allow).
				WithIngressRules([]api.IngressRule{{
			ToPorts: combineL4L7(allowNamedPort80, allowHTTPRoot),
		}})
	lblsL3__AllowFoo = labels.ParseLabelArray("l3-allow-foo")
	ruleL3__AllowFoo = api.NewRule().
				WithLabels(lblsL3__AllowFoo).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowFooL3_},
			},
		}})
	lblsL3__AllowBar = labels.ParseLabelArray("l3-allow-bar")
	ruleL3__AllowBar = api.NewRule().
				WithLabels(lblsL3__AllowBar).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowBarL3_},
			},
		}})
	lblsL3L4AllowBar     = labels.ParseLabelArray("l3l4-allow-bar")
	ruleL3L4AllowBarAuth = api.NewRule().
				WithLabels(lblsL3L4AllowBar).
				WithIngressRules([]api.IngressRule{{
			ToPorts: allowPort80,
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowBarL3_},
			},
			Authentication: &api.Authentication{
				Mode: api.AuthenticationModeAlwaysFail,
			},
		}})
	ruleL3__AllowBarAuth = api.NewRule().
				WithLabels(lblsL3__AllowBar).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{allowBarL3_},
			},
			Authentication: &api.Authentication{
				Mode: api.AuthenticationModeAlwaysFail,
			},
		}})
	lbls____AllowAll = labels.ParseLabelArray("allow-all")
	rule____AllowAll = api.NewRule().
				WithLabels(lbls____AllowAll).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
			},
		}})
	rule____AllowAllAuth = api.NewRule().
				WithLabels(lbls____AllowAll).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
			},
			Authentication: &api.Authentication{
				Mode: api.AuthenticationModeRequired,
			},
		}})
	lblsAllowAllIngress = labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyIngress, labels.LabelSourceReserved),
	}

	lbls_____NoDeny = labels.ParseLabelArray("deny")
	rule_____NoDeny = api.NewRule().
			WithLabels(lbls_____NoDeny).
			WithIngressRules([]api.IngressRule{{}})

	lblsL3_____Deny = labels.ParseLabelArray("l3-deny")
	ruleL3_____Deny = api.NewRule().
			WithLabels(lblsL3_____Deny).
			WithIngressDenyRules([]api.IngressDenyRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{denyFooL3__},
			},
			ToPorts: denyAllL4_,
		}})

	lbls__L4___Deny = labels.ParseLabelArray("l4-deny")
	rule__L4___Deny = api.NewRule().
			WithLabels(lbls__L4___Deny).
			WithIngressDenyRules([]api.IngressDenyRule{{
			ToPorts: denyPort80,
		}})

	lblsL3L4___Deny = labels.ParseLabelArray("l3l4-deny")
	ruleL3L4___Deny = api.NewRule().
			WithLabels(lblsL3L4___Deny).
			WithIngressDenyRules([]api.IngressDenyRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{denyFooL3__},
			},
			ToPorts: denyPort80,
		}})

	// Desired map keys for L3, L3-dependent L4, L4
	mapKeyAllowFoo__ = IngressKey().WithIdentity(identityFoo)
	mapKeyAllowBar__ = IngressKey().WithIdentity(identityBar)
	mapKeyAllowBarL4 = IngressKey().WithIdentity(identityBar).WithTCPPort(80)
	mapKeyAllowFooL4 = IngressKey().WithIdentity(identityFoo).WithTCPPort(80)
	mapKeyDeny_Foo__ = mapKeyAllowFoo__
	mapKeyDeny_FooL4 = mapKeyAllowFooL4
	mapKeyAllow___L4 = IngressKey().WithTCPPort(80)
	mapKeyDeny____L4 = mapKeyAllow___L4
	mapKeyAllowAll__ = IngressKey()
	mapKeyAllowAllE_ = EgressKey()
	// Desired map entries for no L7 redirect / redirect to Proxy
	mapEntryL7None_ = func(lbls ...labels.LabelArray) mapStateEntry {
		return allowEntry().withLabels(lbls)
	}
	mapEntryL7ExplicitAuth_ = func(at AuthType, lbls ...labels.LabelArray) mapStateEntry {
		return allowEntry().withLabels(lbls).withExplicitAuth(at)
	}
	mapEntryL7DerivedAuth_ = func(at AuthType, lbls ...labels.LabelArray) mapStateEntry {
		return allowEntry().withLabels(lbls).withDerivedAuth(at)
	}
	mapEntryL7Deny = func(lbls ...labels.LabelArray) mapStateEntry {
		return denyEntry().withLabels(lbls)
	}
	mapEntryL7Proxy = func(lbls ...labels.LabelArray) mapStateEntry {
		return allowEntry().withLabels(lbls).withHTTPProxyPort(1)
	}
)

// combineL4L7 returns a new PortRule that refers to the specified l4 ports and
// l7 rules.
func combineL4L7(l4 []api.PortRule, l7 *api.L7Rules) []api.PortRule {
	result := make([]api.PortRule, 0, len(l4))
	for _, pr := range l4 {
		result = append(result, api.PortRule{
			Ports: pr.Ports,
			Rules: l7,
		})
	}
	return result
}

// policyDistillery is a convenience wrapper around the existing policy engine,
// allowing simple direct evaluation of L3 and L4 state into "MapState".
type policyDistillery struct {
	*Repository
	log io.Writer
}

func newPolicyDistillery(t testing.TB, selectorCache *SelectorCache) *policyDistillery {
	ret := &policyDistillery{
		Repository: NewPolicyRepository(hivetest.Logger(t), nil, nil, envoypolicy.NewEnvoyL7RulesTranslator(hivetest.Logger(t), certificatemanager.NewMockSecretManagerInline()), nil, api.NewPolicyMetricsNoop()),
	}
	ret.selectorCache = selectorCache
	return ret
}

func (d *policyDistillery) WithLogBuffer(w io.Writer) *policyDistillery {
	return &policyDistillery{
		Repository: d.Repository,
		log:        w,
	}
}

// distillEndpointPolicy distills the policy repository into an EndpointPolicy
// Caller is responsible for Ready() & Detach() when done with the policy
func (d *policyDistillery) distillEndpointPolicy(logger *slog.Logger, owner PolicyOwner, identity *identity.Identity) (*EndpointPolicy, error) {
	sp, _, err := d.Repository.GetSelectorPolicy(identity, 0, &dummyPolicyStats{}, owner.GetID())
	if err != nil {
		return nil, fmt.Errorf("failed to calculate policy: %w", err)
	}
	epp := sp.DistillPolicy(logger, owner, testRedirects)
	if epp == nil {
		return nil, errors.New("policy distillation failure")
	}
	return epp, nil
}

// distillPolicy distills the policy repository into a set of bpf map state
// entries for an endpoint with the specified labels.
func (d *policyDistillery) distillPolicy(logger *slog.Logger, owner PolicyOwner, identity *identity.Identity) (mapState, error) {
	epp, err := d.distillEndpointPolicy(logger, owner, identity)
	if err != nil {
		return emptyMapState(logger), err
	}

	// Remove the allow-all egress entry that's generated by default. This is
	// because this test suite doesn't have a notion of traffic direction, so
	// the extra egress allow-all is technically correct, but omitted from the
	// expected output that's asserted against for the sake of brevity.
	if entry, ok := epp.policyMapState.get(mapKeyAllowAllE_); ok && !entry.IsDeny() {
		epp.policyMapState.delete(mapKeyAllowAllE_)
	}
	epp.Ready()
	epp.Detach(logger)

	return epp.policyMapState, nil
}

// Perm calls f with each permutation of a.
func Perm[X any](a []X, f func([]X)) {
	perm(a, f, 0)
}

// Permute the values at index i to len(a)-1.
func perm[X any](a []X, f func([]X), i int) {
	if i > len(a) {
		f(a)
		return
	}
	perm(a, f, i+1)
	for j := i + 1; j < len(a); j++ {
		a[i], a[j] = a[j], a[i]
		perm(a, f, i+1)
		a[i], a[j] = a[j], a[i]
	}
}

func Test_Perm(t *testing.T) {
	var res []string
	expected := []string{
		"abc",
		"acb",
		"bac",
		"bca",
		"cba",
		"cab",
	}
	Perm([]rune("abc"), func(x []rune) { res = append(res, string(x)) })
	assert.Equal(t, expected, res, "invalid permutations")
}

func testMapState(t testing.TB, initMap mapStateMap) mapState {
	return emptyMapState(hivetest.Logger(t)).withState(initMap)
}

func Test_MergeL3(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	identityCache := identity.IdentityMap{
		identityFoo: labelsFoo,
		identityBar: labelsBar,
	}
	selectorCache := testNewSelectorCache(hivetest.Logger(t), identityCache)

	type authResult map[identity.NumericIdentity]AuthTypes
	tests := []struct {
		test   int
		rules  api.Rules
		result mapState
		auths  authResult
	}{
		{
			0,
			api.Rules{ruleL3__AllowFoo, ruleL3__AllowBar},
			testMapState(t, mapStateMap{
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowBar__: mapEntryL7None_(lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{},
				identityFoo: AuthTypes{},
			},
		},
		{
			1,
			api.Rules{ruleL3__AllowFoo, ruleL3L4__Allow},
			testMapState(t, mapStateMap{
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow),
			}),
			authResult{
				identityBar: AuthTypes{},
				identityFoo: AuthTypes{},
			},
		},
		{
			2,
			api.Rules{ruleL3__AllowFoo, ruleL3__AllowBarAuth},
			testMapState(t, mapStateMap{
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowBar__: mapEntryL7ExplicitAuth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identityFoo: AuthTypes{},
			},
		},
		{
			3,
			api.Rules{ruleL3__AllowFoo, ruleL3__AllowBarAuth, rule__L4__AllowAuth},
			testMapState(t, mapStateMap{
				mapKeyAllow___L4: mapEntryL7ExplicitAuth_(AuthTypeSpire, lbls__L4__Allow),
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowBar__: mapEntryL7ExplicitAuth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeAlwaysFail: struct{}{}, AuthTypeSpire: struct{}{}},
				identityFoo: AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			4,
			api.Rules{rule____AllowAll, ruleL3__AllowBarAuth},
			testMapState(t, mapStateMap{
				mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll),
				mapKeyAllowBar__: mapEntryL7ExplicitAuth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identityFoo: AuthTypes{},
			},
		},
		{
			5,
			api.Rules{rule____AllowAllAuth, ruleL3__AllowBar},
			testMapState(t, mapStateMap{
				mapKeyAllowAll__: mapEntryL7ExplicitAuth_(AuthTypeSpire, lbls____AllowAll),
				mapKeyAllowBar__: mapEntryL7None_(lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeSpire: struct{}{}},
				identityFoo: AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			6,
			api.Rules{rule____AllowAllAuth, rule__L4__Allow},
			testMapState(t, mapStateMap{
				mapKeyAllowAll__: mapEntryL7ExplicitAuth_(AuthTypeSpire, lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7DerivedAuth_(AuthTypeSpire, lbls__L4__Allow),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeSpire: struct{}{}},
				identityFoo: AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			7,
			api.Rules{rule____AllowAllAuth, ruleL3__AllowBar, rule__L4__Allow},
			testMapState(t, mapStateMap{
				mapKeyAllowAll__: mapEntryL7ExplicitAuth_(AuthTypeSpire, lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7DerivedAuth_(AuthTypeSpire, lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7DerivedAuth_(AuthTypeDisabled, lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeSpire: struct{}{}},
				identityFoo: AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			8,
			api.Rules{rule____AllowAll, ruleL3__AllowBar, rule__L4__Allow},
			testMapState(t, mapStateMap{
				mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7None_(lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{},
				identityFoo: AuthTypes{},
			},
		},
		{
			9,
			api.Rules{rule____AllowAll, rule__L4__Allow, ruleL3__AllowBarAuth},
			testMapState(t, mapStateMap{
				mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7ExplicitAuth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identityFoo: AuthTypes{},
			},
		},
		{
			10, // Same as 9, but the L3L4 entry is created by an explicit rule.
			api.Rules{rule____AllowAll, rule__L4__Allow, ruleL3__AllowBarAuth, ruleL3L4AllowBarAuth},
			testMapState(t, mapStateMap{
				mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7ExplicitAuth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
				mapKeyAllowBarL4: mapEntryL7ExplicitAuth_(AuthTypeAlwaysFail, lblsL3L4AllowBar),
			}),
			authResult{
				identityBar: AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identityFoo: AuthTypes{},
			},
		},
	}

	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)
	for _, tt := range tests {
		for i, r := range tt.rules {
			tt.rules[i] = r.WithEndpointSelector(selectFoo_)
		}

		round := 0
		Perm(tt.rules, func(rules []*api.Rule) {
			round++

			repo := newPolicyDistillery(t, selectorCache)
			_, _ = repo.MustAddList(rules)

			t.Run(fmt.Sprintf("permutation_%d-%d", tt.test, round), func(t *testing.T) {
				logBuffer := new(bytes.Buffer)
				repo = repo.WithLogBuffer(logBuffer)
				mapstate, err := repo.distillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, identity)
				if err != nil {
					t.Errorf("Policy resolution failure: %s", err)
				}
				if equal := assert.True(t, mapstate.Equal(&tt.result), mapstate.diff(&tt.result)); !equal {
					t.Logf("Rules:\n%s\n\n", api.Rules(rules).String())
					t.Logf("Policy Trace: \n%s\n", logBuffer.String())
					t.Errorf("Policy obtained didn't match expected for endpoint %s:\nObtained: %v\nExpected: %v", labelsFoo, mapstate, tt.result)
				}
				for remoteID, expectedAuthTypes := range tt.auths {
					authTypes := repo.GetAuthTypes(identity.ID, remoteID)
					if !maps.Equal(authTypes, expectedAuthTypes) {
						t.Errorf("Incorrect AuthTypes result for remote ID %d: obtained %v, expected %v", remoteID, authTypes, expectedAuthTypes)
					}
				}
			})
		})
	}
}

// The following variables names are derived from the following google sheet
// https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw/edit?usp=sharing

const (
	L3L4KeyL3 = iota
	L3L4KeyL4
	L3L4KeyL7
	L3L4KeyDeny
	L4KeyL3
	L4KeyL4
	L4KeyL7
	L4KeyDeny
	L3KeyL3
	L3KeyL4
	L3KeyL7
	L3KeyDeny
	Total
)

// fieldsSet is the representation of the values set in the cells M8-P8, Q8-T8
// and U8-X8.
type fieldsSet struct {
	L3   *bool
	L4   *bool
	L7   *bool
	Deny *bool
}

// generatedBPFKey is the representation of the values set in the cells [M:P]6,
// [Q:T]6 and [U:X]6.
type generatedBPFKey struct {
	L3L4Key fieldsSet
	L4Key   fieldsSet
	L3Key   fieldsSet
}

func parseFieldBool(s string) *bool {
	switch s {
	case "X":
		return nil
	case "0":
		return func() *bool { a := false; return &a }()
	case "1":
		return func() *bool { a := true; return &a }()
	default:
		panic("Unknown value")
	}
}

func parseTable(test string) generatedBPFKey {
	// Remove all consecutive white space characters and return the charts that
	// need want to parse.
	fields := strings.Fields(test)
	if len(fields) != Total {
		panic("Wrong number of expected results")
	}
	return generatedBPFKey{
		L3L4Key: fieldsSet{
			L3:   parseFieldBool(fields[L3L4KeyL3]),
			L4:   parseFieldBool(fields[L3L4KeyL4]),
			L7:   parseFieldBool(fields[L3L4KeyL7]),
			Deny: parseFieldBool(fields[L3L4KeyDeny]),
		},
		L4Key: fieldsSet{
			L3:   parseFieldBool(fields[L4KeyL3]),
			L4:   parseFieldBool(fields[L4KeyL4]),
			L7:   parseFieldBool(fields[L4KeyL7]),
			Deny: parseFieldBool(fields[L4KeyDeny]),
		},
		L3Key: fieldsSet{
			L3:   parseFieldBool(fields[L3KeyL3]),
			L4:   parseFieldBool(fields[L3KeyL4]),
			L7:   parseFieldBool(fields[L3KeyL7]),
			Deny: parseFieldBool(fields[L3KeyDeny]),
		},
	}
}

// testCaseToMapState generates the expected MapState logic. This function is
// an implementation of the expected behavior. Any relation between this
// function and non unit-test code should be seen as coincidental.
// The algorithm represented in this function should be the source of truth
// of our expectations when enforcing multiple types of policies.
func testCaseToMapState(t2 *testing.T, t generatedBPFKey) mapState {
	m := emptyMapState(hivetest.Logger(t2))

	if t.L3Key.L3 != nil {
		if t.L3Key.Deny != nil && *t.L3Key.Deny {
			m.upsert(mapKeyDeny_Foo__, mapEntryL7Deny())
		} else {
			// If L7 is not set or if it explicitly set but it's false
			if t.L3Key.L7 == nil || !*t.L3Key.L7 {
				m.upsert(mapKeyAllowFoo__, mapEntryL7None_())
			}
			// there's no "else" because we don't support L3L7 policies, i.e.,
			// a L4 port needs to be specified.
		}
	}
	if t.L4Key.L3 != nil {
		if t.L4Key.Deny != nil && *t.L4Key.Deny {
			m.upsert(mapKeyDeny____L4, mapEntryL7Deny())
		} else {
			// If L7 is not set or if it explicitly set but it's false
			if t.L4Key.L7 == nil || !*t.L4Key.L7 {
				m.upsert(mapKeyAllow___L4, mapEntryL7None_())
			} else {
				// L7 is set and it's true then we should expected a mapEntry
				// with L7 redirection.
				m.upsert(mapKeyAllow___L4, mapEntryL7Proxy())
			}
		}
	}
	if t.L3L4Key.L3 != nil {
		if t.L3L4Key.Deny != nil && *t.L3L4Key.Deny {
			m.upsert(mapKeyDeny_FooL4, mapEntryL7Deny())
		} else {
			// If L7 is not set or if it explicitly set but it's false
			if t.L3L4Key.L7 == nil || !*t.L3L4Key.L7 {
				m.upsert(mapKeyAllowFooL4, mapEntryL7None_())
			} else {
				// L7 is set and it's true then we should expected a mapEntry
				// with L7 redirection only if we haven't set it already
				// for an existing L4-only.
				if t.L4Key.L7 == nil || !*t.L4Key.L7 {
					m.upsert(mapKeyAllowFooL4, mapEntryL7Proxy())
				}
			}
		}
	}

	return m
}

func generateMapStates(t *testing.T) []mapState {
	rawTestTable := []string{
		"X	X	X	X	X	X	X	X	X	X	X	X", // 0
		"X	X	X	X	X	X	X	X	1	0	0	0",
		"X	X	X	X	0	1	0	0	X	X	X	X",
		"X	X	X	X	0	1	0	0	1	0	0	0",
		"1	1	0	0	X	X	X	X	X	X	X	X",
		"1	1	0	0	X	X	X	X	1	0	0	0", // 5
		"X	X	X	X	0	1	0	0	X	X	X	X",
		"X	X	X	X	0	1	0	0	1	0	0	0",
		"X	X	X	X	0	1	1	0	X	X	X	X",
		"X	X	X	X	0	1	1	0	1	0	0	0",
		"X	X	X	X	0	1	1	0	X	X	X	X", // 10
		"X	X	X	X	0	1	1	0	1	0	0	0",
		"1	1	1	0	0	1	1	0	X	X	X	X",
		"1	1	1	0	0	1	1	0	1	0	0	0",
		"1	1	1	0	0	1	1	0	X	X	X	X",
		"1	1	1	0	0	1	1	0	1	0	0	0", // 15
		"1	1	1	0	X	X	X	X	X	X	X	X",
		"1	1	1	0	X	X	X	X	1	0	0	0",
		"1	1	1	0	0	1	0	0	X	X	X	X",
		"1	1	1	0	0	1	0	0	1	0	0	0",
		"1	1	1	0	X	X	X	X	X	X	X	X", // 20
		"1	1	1	0	X	X	X	X	1	0	0	0",
		"1	1	1	0	0	1	0	0	X	X	X	X",
		"1	1	1	0	0	1	0	0	1	0	0	0",
		"1	1	1	0	0	1	1	0	X	X	X	X",
		"1	1	1	0	0	1	1	0	1	0	0	0", // 25
		"1	1	1	0	0	1	1	0	X	X	X	X",
		"1	1	1	0	0	1	1	0	1	0	0	0",
		"1	1	1	0	0	1	1	0	X	X	X	X",
		"1	1	1	0	0	1	1	0	1	0	0	0",
		"1	1	1	0	0	1	1	0	X	X	X	X", // 30
		"1	1	1	0	0	1	1	0	1	0	0	0",

		"X	X	X	X	X	X	X	X	1	0	0	1", // 32
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",

		"X	X	X	X	0	1	0	1	X	X	X	X", // 64
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",

		"X	X	X	X	0	1	0	1	1	0	0	1", // 96
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",
		"X	X	X	X	0	1	0	1	1	0	0	1",

		"1	1	0	1	X	X	X	X	X	X	X	X", // 128
		"1	1	0	1	X	X	X	X	1	0	0	0",
		"1	1	0	1	0	1	0	0	X	X	X	X",
		"1	1	0	1	0	1	0	0	1	0	0	0",
		"1	1	0	1	X	X	X	X	X	X	X	X",
		"1	1	0	1	X	X	X	X	1	0	0	0",
		"1	1	0	1	0	1	0	0	X	X	X	X",
		"1	1	0	1	0	1	0	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",
		"1	1	0	1	X	X	X	X	X	X	X	X",
		"1	1	0	1	X	X	X	X	1	0	0	0",
		"1	1	0	1	0	1	0	0	X	X	X	X",
		"1	1	0	1	0	1	0	0	1	0	0	0",
		"1	1	0	1	X	X	X	X	X	X	X	X",
		"1	1	0	1	X	X	X	X	1	0	0	0",
		"1	1	0	1	0	1	0	0	X	X	X	X",
		"1	1	0	1	0	1	0	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",
		"1	1	0	1	0	1	1	0	X	X	X	X",
		"1	1	0	1	0	1	1	0	1	0	0	0",

		"X	X	X	X	X	X	X	X	1	0	0	1", // 160
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"X	X	X	X	X	X	X	X	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	0	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",
		"1	1	0	1	0	1	1	0	1	0	0	1",

		"X	X	X	X	0	1	0	1	X	X	X	X", // 192
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",
		"X	X	X	X	0	1	0	1	X	X	X	X",
		"X	X	X	X	0	1	0	1	1	0	0	0",

		"X	X	X	X	1	1	0	1	1	0	0	1", // 224
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
		"X	X	X	X	1	1	0	1	1	0	0	1",
	}
	mapStates := make([]mapState, 0, len(rawTestTable))
	for _, rawTest := range rawTestTable {
		testCase := parseTable(rawTest)
		mapState := testCaseToMapState(t, testCase)
		mapStates = append(mapStates, mapState)
	}

	return mapStates
}

func generateRule(testCase int) api.Rules {
	rulesIdx := api.Rules{
		ruleL3____Allow,
		rule__L4__Allow,
		ruleL3L4__Allow,
		rule__L4L7Allow,
		ruleL3L4L7Allow,
		// denyIdx
		ruleL3_____Deny,
		rule__L4___Deny,
		ruleL3L4___Deny,
	}
	rules := make(api.Rules, 0, len(rulesIdx))
	for i := len(rulesIdx) - 1; i >= 0; i-- {
		if ((testCase >> i) & 0x1) != 0 {
			rules = append(rules, rulesIdx[i])
		} else {
			if i >= 5 { // denyIdx
				rules = append(rules, rule_____NoDeny)
			} else {
				rules = append(rules, rule____NoAllow)
			}
		}
	}
	return rules
}

func Test_MergeRules(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(hivetest.Logger(t), identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     int
		rules    api.Rules
		expected mapState
	}{
		// The following table is derived from the Google Doc here:
		// https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw/edit?usp=sharing
		//
		//  Rule 0                   | Rule 1         | Rule 2         | Rule 3         | Rule 4         | Rule 5         | Rule 6         | Rule 7         | Desired BPF map state
		{0, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, nil)},
		{1, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{2, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{3, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{4, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow)})},
		{5, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{6, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},                                                     // identical L3L4 entry suppressed
		{7, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
		{8, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},
		{9, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{10, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},
		{11, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{12, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                      // L3L4 entry suppressed to allow L4-only entry to redirect
		{13, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                  // L3L4 entry suppressed to allow L4-only entry to redirect
		{14, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},                                                     // L3L4 entry suppressed to allow L4-only entry to redirect
		{15, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // L3L4 entry suppressed to allow L4-only entry to redirect
		{16, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow)})},
		{17, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{18, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{19, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{20, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow)})},
		{21, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{22, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{23, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{24, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                      // identical L3L4 entry suppressed
		{25, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                  // identical L3L4 entry suppressed
		{26, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},                                                     // identical L3L4 entry suppressed
		{27, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
		{28, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                      // identical L3L4 entry suppressed
		{29, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                  // identical L3L4 entry suppressed
		{30, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},                                                     // identical L3L4 entry suppressed
		{31, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
	}

	expectedMapState := generateMapStates(t)
	// Add the auto generated test cases for the deny policies
	generatedIdx := 32
	for i := generatedIdx; i < 256; i++ {
		tests = append(tests,
			struct {
				test     int
				rules    api.Rules
				expected mapState
			}{
				test:     i,
				rules:    generateRule(i),
				expected: expectedMapState[i],
			})
	}

	for i, tt := range tests {
		repo := newPolicyDistillery(t, selectorCache)
		generatedRule := generateRule(tt.test)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			// Ignore generated rules as they lap LabelArrayList which would
			// make the tests fail.
			if i < generatedIdx {
				if equal := assert.True(t, mapstate.Equal(&tt.expected), mapstate.diff(&tt.expected)); !equal {
					require.EqualExportedValuesf(t, tt.expected, mapstate, "Policy obtained didn't match expected for endpoint %s", labelsFoo)
					t.Logf("Rules:\n%s\n\n", tt.rules.String())
					t.Logf("Policy Trace: \n%s\n", logBuffer.String())
					t.Errorf("Policy obtained didn't match expected for endpoint %s", labelsFoo)
				}
			}
			if equal := assert.EqualExportedValues(t, expectedMapState[tt.test], mapstate); !equal {
				t.Logf("Rules:\n%s\n\n", tt.rules.String())
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Error("Policy obtained didn't match expected for endpoint")
			}
			if equal := assert.ElementsMatch(t, tt.rules, generatedRule); !equal {
				t.Logf("Rules:\n%s\n\n", tt.rules.String())
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Error("Generated rules didn't match manual rules")
			}
		})
	}
}

func Test_MergeRulesWithNamedPorts(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(hivetest.Logger(t), identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     int
		rules    api.Rules
		expected mapState
	}{
		// The following table is derived from the Google Doc here:
		// https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw/edit?usp=sharing
		//
		//  Rule 0                   | Rule 1         | Rule 2         | Rule 3         | Rule 4         | Rule 5         | Rule 6         | Rule 7         | Desired BPF map state
		{0, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, nil)},
		{1, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{2, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{3, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{4, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow)})},
		{5, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{6, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},                                                     // identical L3L4 entry suppressed
		{7, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
		{8, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},
		{9, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{10, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},
		{11, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{12, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                        // L3L4 entry suppressed to allow L4-only entry to redirect
		{13, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                    // L3L4 entry suppressed to allow L4-only entry to redirect
		{14, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},                                                     // L3L4 entry suppressed to allow L4-only entry to redirect
		{15, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // L3L4 entry suppressed to allow L4-only entry to redirect
		{16, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow)})},
		{17, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{18, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{19, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{20, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow)})},
		{21, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{22, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{23, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4__Allow, lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{24, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                          // identical L3L4 entry suppressed
		{25, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                      // identical L3L4 entry suppressed
		{26, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},                                                       // identical L3L4 entry suppressed
		{27, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},   // identical L3L4 entry suppressed
		{28, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                        // identical L3L4 entry suppressed
		{29, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                    // identical L3L4 entry suppressed
		{30, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow)})},                                                     // identical L3L4 entry suppressed
		{31, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, testMapState(t, mapStateMap{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4__Allow, lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
	}
	for _, tt := range tests {
		repo := newPolicyDistillery(t, selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			require.Truef(t, mapstate.Equal(&tt.expected),
				"Policy obtained didn't match expected for endpoint %s:\n%s", labelsFoo, mapstate.diff(&tt.expected))
		})
	}
}

func Test_AllowAll(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	identityCache := identity.IdentityMap{
		identityFoo: labelsFoo,
		identityBar: labelsBar,
	}
	selectorCache := testNewSelectorCache(hivetest.Logger(t), identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     int
		selector api.EndpointSelector
		rules    api.Rules
		expected mapState
	}{
		{0, api.EndpointSelectorNone, api.Rules{rule____AllowAll}, testMapState(t, mapStateMap{mapKeyAllowAll__: mapEntryL7None_(lblsAllowAllIngress)})},
		{1, api.WildcardEndpointSelector, api.Rules{rule____AllowAll}, testMapState(t, mapStateMap{mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll)})},
	}

	for _, tt := range tests {
		repo := newPolicyDistillery(t, selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(tt.selector)
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal := assert.True(t, mapstate.Equal(&tt.expected), mapstate.diff(&tt.expected)); !equal {
				t.Logf("Rules:\n%s\n\n", tt.rules.String())
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy obtained didn't match expected for endpoint %s", labelsFoo)
			}
		})
	}
}

var (
	ruleAllowAllIngress = api.NewRule().WithIngressRules([]api.IngressRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
		}}}).WithEndpointSelector(api.WildcardEndpointSelector)

	ruleL3DenyWorld = api.NewRule().WithIngressDenyRules([]api.IngressDenyRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromEntities: api.EntitySlice{api.EntityWorld},
		},
	}}).WithEgressDenyRules([]api.EgressDenyRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToEntities: api.EntitySlice{api.EntityWorld},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)

	cpyRule                   = *ruleL3DenyWorld
	ruleL3DenyWorldWithLabels = (&cpyRule).WithLabels(labels.LabelWorld.LabelArray())
	worldReservedID           = identity.ReservedIdentityWorld
	worldReservedIDIPv4       = identity.ReservedIdentityWorldIPv4
	worldReservedIDIPv6       = identity.ReservedIdentityWorldIPv6
	mapKeyL3WorldIngress      = IngressKey().WithIdentity(worldReservedID)
	mapKeyL3WorldIngressIPv4  = IngressKey().WithIdentity(worldReservedIDIPv4)
	mapKeyL3WorldIngressIPv6  = IngressKey().WithIdentity(worldReservedIDIPv6)
	mapKeyL3WorldEgress       = EgressKey().WithIdentity(worldReservedID)
	mapKeyL3WorldEgressIPv4   = EgressKey().WithIdentity(worldReservedIDIPv4)
	mapKeyL3WorldEgressIPv6   = EgressKey().WithIdentity(worldReservedIDIPv6)

	AllowEntry    = types.AllowEntry()
	DenyEntry     = types.DenyEntry()
	mapEntryDeny  = NewMapStateEntry(DenyEntry).withLabels(labels.LabelArrayList{nil})
	mapEntryAllow = NewMapStateEntry(AllowEntry).withLabels(labels.LabelArrayList{nil})

	worldLabelArrayList         = labels.LabelArrayList{labels.LabelWorld.LabelArray()}
	mapEntryWorldDenyWithLabels = NewMapStateEntry(DenyEntry).withLabels(worldLabelArrayList)

	worldIPIdentity = localIdentity(16324)
	worldIPCIDR     = api.CIDR("192.0.2.3/32")
	lblWorldIP      = labels.GetCIDRLabels(netip.MustParsePrefix(string(worldIPCIDR)))
	hostIPv4        = api.CIDR("172.19.0.1/32")
	hostIPv6        = api.CIDR("fc00:c111::3/64")
	lblHostIPv4CIDR = labels.GetCIDRLabels(netip.MustParsePrefix(string(hostIPv4)))
	lblHostIPv6CIDR = labels.GetCIDRLabels(netip.MustParsePrefix(string(hostIPv6)))

	ruleL3AllowWorldIP = api.NewRule().WithIngressRules([]api.IngressRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromCIDR: api.CIDRSlice{worldIPCIDR},
		},
	}}).WithEgressRules([]api.EgressRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: api.CIDRSlice{worldIPCIDR},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)

	worldSubnetIdentity = localIdentity(16325)
	worldSubnet         = api.CIDR("192.0.2.0/24")
	worldSubnetRule     = api.CIDRRule{
		Cidr: worldSubnet,
	}
	lblWorldSubnet   = labels.GetCIDRLabels(netip.MustParsePrefix(string(worldSubnet)))
	ruleL3DenySubnet = api.NewRule().WithIngressDenyRules([]api.IngressDenyRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromCIDRSet: api.CIDRRuleSlice{worldSubnetRule},
		},
	}}).WithEgressDenyRules([]api.EgressDenyRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDRSet: api.CIDRRuleSlice{worldSubnetRule},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)
	mapKeyL3SubnetIngress = IngressKey().WithIdentity(worldSubnetIdentity)
	mapKeyL3SubnetEgress  = EgressKey().WithIdentity(worldSubnetIdentity)

	ruleL3DenySmallerSubnet = api.NewRule().WithIngressDenyRules([]api.IngressDenyRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromCIDRSet: api.CIDRRuleSlice{api.CIDRRule{Cidr: worldIPCIDR}},
		},
	}}).WithEgressDenyRules([]api.EgressDenyRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDRSet: api.CIDRRuleSlice{api.CIDRRule{Cidr: worldIPCIDR}},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)

	ruleL3AllowLargerSubnet = api.NewRule().WithIngressRules([]api.IngressRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromCIDRSet: api.CIDRRuleSlice{api.CIDRRule{Cidr: worldSubnet}},
		},
	}}).WithEgressRules([]api.EgressRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDRSet: api.CIDRRuleSlice{api.CIDRRule{Cidr: worldSubnet}},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)

	mapKeyL3SmallerSubnetIngress = IngressKey().WithIdentity(worldIPIdentity)
	mapKeyL3SmallerSubnetEgress  = EgressKey().WithIdentity(worldIPIdentity)

	ruleL3AllowHostEgress = api.NewRule().WithEgressRules([]api.EgressRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDRSet: api.CIDRRuleSlice{api.CIDRRule{Cidr: hostIPv4}, api.CIDRRule{Cidr: hostIPv6}},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)

	mapKeyL3UnknownIngress            = IngressKey()
	mapEntryL3UnknownIngress          = newAllowEntryWithLabels(LabelsAllowAnyIngress)
	mapKeyL3HostEgress                = EgressKey().WithIdentity(identity.ReservedIdentityHost)
	ruleL3L4Port8080ProtoAnyDenyWorld = api.NewRule().WithIngressDenyRules([]api.IngressDenyRule{
		{
			ToPorts: api.PortDenyRules{
				api.PortDenyRule{
					Ports: []api.PortProtocol{
						{
							Port:     "8080",
							Protocol: api.ProtoAny,
						},
					},
				},
			},
			IngressCommonRule: api.IngressCommonRule{
				FromEntities: api.EntitySlice{api.EntityWorld},
			},
		},
	}).WithEgressDenyRules([]api.EgressDenyRule{
		{
			ToPorts: api.PortDenyRules{
				api.PortDenyRule{
					Ports: []api.PortProtocol{
						{
							Port:     "8080",
							Protocol: api.ProtoAny,
						},
					},
				},
			},
			EgressCommonRule: api.EgressCommonRule{
				ToEntities: api.EntitySlice{api.EntityWorld},
			},
		},
	}).WithEndpointSelector(api.WildcardEndpointSelector)
	mapKeyL3L4Port8080ProtoTCPWorldIngress  = IngressKey().WithIdentity(worldReservedID).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoTCPWorldEgress   = EgressKey().WithIdentity(worldReservedID).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldIngress  = IngressKey().WithIdentity(worldReservedID).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldEgress   = EgressKey().WithIdentity(worldReservedID).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldIngress = IngressKey().WithIdentity(worldReservedID).WithSCTPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldEgress  = EgressKey().WithIdentity(worldReservedID).WithSCTPPort(8080)

	mapKeyL3L4Port8080ProtoTCPWorldIPv4Ingress  = IngressKey().WithIdentity(worldReservedIDIPv4).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoTCPWorldIPv4Egress   = EgressKey().WithIdentity(worldReservedIDIPv4).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldIPv4Ingress  = IngressKey().WithIdentity(worldReservedIDIPv4).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldIPv4Egress   = EgressKey().WithIdentity(worldReservedIDIPv4).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldIPv4Ingress = IngressKey().WithIdentity(worldReservedIDIPv4).WithSCTPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldIPv4Egress  = EgressKey().WithIdentity(worldReservedIDIPv4).WithSCTPPort(8080)

	mapKeyL3L4Port8080ProtoTCPWorldIPv6Ingress  = IngressKey().WithIdentity(worldReservedIDIPv6).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoTCPWorldIPv6Egress   = EgressKey().WithIdentity(worldReservedIDIPv6).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldIPv6Ingress  = IngressKey().WithIdentity(worldReservedIDIPv6).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldIPv6Egress   = EgressKey().WithIdentity(worldReservedIDIPv6).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldIPv6Ingress = IngressKey().WithIdentity(worldReservedIDIPv6).WithSCTPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldIPv6Egress  = EgressKey().WithIdentity(worldReservedIDIPv6).WithSCTPPort(8080)

	mapKeyL3L4Port8080ProtoTCPWorldSNIngress  = IngressKey().WithIdentity(worldSubnetIdentity).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoTCPWorldSNEgress   = EgressKey().WithIdentity(worldSubnetIdentity).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldSNIngress  = IngressKey().WithIdentity(worldSubnetIdentity).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldSNEgress   = EgressKey().WithIdentity(worldSubnetIdentity).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldSNIngress = IngressKey().WithIdentity(worldSubnetIdentity).WithSCTPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldSNEgress  = EgressKey().WithIdentity(worldSubnetIdentity).WithSCTPPort(8080)

	mapKeyL3L4Port8080ProtoTCPWorldIPIngress  = IngressKey().WithIdentity(worldIPIdentity).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoTCPWorldIPEgress   = EgressKey().WithIdentity(worldIPIdentity).WithTCPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldIPIngress  = IngressKey().WithIdentity(worldIPIdentity).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoUDPWorldIPEgress   = EgressKey().WithIdentity(worldIPIdentity).WithUDPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldIPIngress = IngressKey().WithIdentity(worldIPIdentity).WithSCTPPort(8080)
	mapKeyL3L4Port8080ProtoSCTPWorldIPEgress  = EgressKey().WithIdentity(worldIPIdentity).WithSCTPPort(8080)

	ruleL3AllowWorldSubnet = api.NewRule().WithIngressRules([]api.IngressRule{{
		ToPorts: api.PortRules{
			api.PortRule{
				Ports: []api.PortProtocol{
					{
						Port:     "8080",
						Protocol: api.ProtoAny,
					},
				},
			},
		},
		IngressCommonRule: api.IngressCommonRule{
			FromCIDR: api.CIDRSlice{worldSubnet},
		},
	}}).WithEgressRules([]api.EgressRule{{
		ToPorts: api.PortRules{
			api.PortRule{
				Ports: []api.PortProtocol{
					{
						Port:     "8080",
						Protocol: api.ProtoAny,
					},
				},
			},
		},
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: api.CIDRSlice{worldSubnet},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)

	ruleL3DenyWorldIP = api.NewRule().WithIngressDenyRules([]api.IngressDenyRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromCIDR: api.CIDRSlice{worldIPCIDR},
		},
	}}).WithEgressDenyRules([]api.EgressDenyRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: api.CIDRSlice{worldIPCIDR},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)
	mapKeyAnyIngress                   = IngressKey()
	mapKeyL4AnyPortProtoWorldIPIngress = IngressKey().WithIdentity(worldIPIdentity)
	mapKeyL4AnyPortProtoWorldIPEgress  = EgressKey().WithIdentity(worldIPIdentity)

	ruleL3AllowWorldSubnetNamedPort = api.NewRule().WithIngressRules([]api.IngressRule{{
		ToPorts: api.PortRules{
			api.PortRule{
				Ports: []api.PortProtocol{
					{
						Port:     "http",
						Protocol: api.ProtoTCP,
					},
				},
			},
		},
		IngressCommonRule: api.IngressCommonRule{
			FromCIDR: api.CIDRSlice{worldSubnet},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)
	mapKeyL3L4NamedPortHTTPProtoTCPWorldSubNetIngress = IngressKey().WithIdentity(worldSubnetIdentity).WithTCPPort(80)
	mapKeyL3L4NamedPortHTTPProtoTCPWorldIPIngress     = IngressKey().WithIdentity(worldIPIdentity).WithTCPPort(80)

	ruleL3AllowWorldSubnetPortRange = api.NewRule().WithIngressRules([]api.IngressRule{{
		ToPorts: api.PortRules{
			api.PortRule{
				Ports: []api.PortProtocol{
					{
						Port:     "64",
						EndPort:  127,
						Protocol: api.ProtoTCP,
					},
					{
						Port:     "5",
						EndPort:  10,
						Protocol: api.ProtoTCP,
					},
				},
			},
		},
		IngressCommonRule: api.IngressCommonRule{
			FromCIDR: api.CIDRSlice{worldSubnet},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)
	mapKeyL3L4Port64To127ProtoTCPWorldSubNetIngress = IngressKey().WithIdentity(worldSubnetIdentity).WithTCPPortPrefix(64, 10)
	mapKeyL3L4Port5ProtoTCPWorldSubNetIngress       = IngressKey().WithIdentity(worldSubnetIdentity).WithTCPPort(5)
	mapKeyL3L4Port6To7ProtoTCPWorldSubNetIngress    = IngressKey().WithIdentity(worldSubnetIdentity).WithTCPPortPrefix(6, 15)
	mapKeyL3L4Port8To9ProtoTCPWorldSubNetIngress    = IngressKey().WithIdentity(worldSubnetIdentity).WithTCPPortPrefix(8, 15)
	mapKeyL3L4Port10ProtoTCPWorldSubNetIngress      = IngressKey().WithIdentity(worldSubnetIdentity).WithTCPPort(10)
	mapKeyL3L4Port64To127ProtoTCPWorldIPIngress     = IngressKey().WithIdentity(worldIPIdentity).WithTCPPortPrefix(64, 10)
	mapKeyL3L4Port5ProtoTCPWorldIPIngress           = IngressKey().WithIdentity(worldIPIdentity).WithTCPPort(5)
	mapKeyL3L4Port6To7ProtoTCPWorldIPIngress        = IngressKey().WithIdentity(worldIPIdentity).WithTCPPortPrefix(6, 15)
	mapKeyL3L4Port8To9ProtoTCPWorldIPIngress        = IngressKey().WithIdentity(worldIPIdentity).WithTCPPortPrefix(8, 15)
	mapKeyL3L4Port10ProtoTCPWorldIPIngress          = IngressKey().WithIdentity(worldIPIdentity).WithTCPPort(10)
)

func Test_EnsureDeniesPrecedeAllows(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.ReservedIdentityWorld:        labels.LabelWorld.LabelArray(),
		identity.ReservedIdentityWorldIPv4:    labels.LabelWorldIPv4.LabelArray(),
		identity.ReservedIdentityWorldIPv6:    labels.LabelWorldIPv6.LabelArray(),
		worldIPIdentity:                       lblWorldIP.LabelArray(),     // "192.0.2.3/32"
		worldSubnetIdentity:                   lblWorldSubnet.LabelArray(), // "192.0.2.0/24"
	}
	selectorCache := testNewSelectorCache(hivetest.Logger(t), identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     string
		rules    api.Rules
		expected mapState
	}{
		{"deny_world_no_labels", api.Rules{ruleAllowAllIngress, ruleL3DenyWorld, ruleL3AllowWorldIP}, testMapState(t, mapStateMap{
			mapKeyAnyIngress:             mapEntryAllow,
			mapKeyL3WorldIngress:         mapEntryDeny,
			mapKeyL3WorldIngressIPv4:     mapEntryDeny,
			mapKeyL3WorldIngressIPv6:     mapEntryDeny,
			mapKeyL3WorldEgress:          mapEntryDeny,
			mapKeyL3WorldEgressIPv4:      mapEntryDeny,
			mapKeyL3WorldEgressIPv6:      mapEntryDeny,
			mapKeyL3SubnetIngress:        mapEntryDeny,
			mapKeyL3SubnetEgress:         mapEntryDeny,
			mapKeyL3SmallerSubnetIngress: mapEntryDeny,
			mapKeyL3SmallerSubnetEgress:  mapEntryDeny,
		})}, {"deny_world_with_labels", api.Rules{ruleAllowAllIngress, ruleL3DenyWorldWithLabels, ruleL3AllowWorldIP}, testMapState(t, mapStateMap{
			mapKeyAnyIngress:             mapEntryAllow,
			mapKeyL3WorldIngress:         mapEntryWorldDenyWithLabels,
			mapKeyL3WorldIngressIPv4:     mapEntryWorldDenyWithLabels,
			mapKeyL3WorldIngressIPv6:     mapEntryWorldDenyWithLabels,
			mapKeyL3WorldEgress:          mapEntryWorldDenyWithLabels,
			mapKeyL3WorldEgressIPv4:      mapEntryWorldDenyWithLabels,
			mapKeyL3WorldEgressIPv6:      mapEntryWorldDenyWithLabels,
			mapKeyL3SubnetIngress:        mapEntryWorldDenyWithLabels,
			mapKeyL3SubnetEgress:         mapEntryWorldDenyWithLabels,
			mapKeyL3SmallerSubnetIngress: mapEntryWorldDenyWithLabels,
			mapKeyL3SmallerSubnetEgress:  mapEntryWorldDenyWithLabels,
		})}, {"deny_one_ip_with_a_larger_subnet", api.Rules{ruleAllowAllIngress, ruleL3DenySubnet, ruleL3AllowWorldIP}, testMapState(t, mapStateMap{
			mapKeyAnyIngress:             mapEntryAllow,
			mapKeyL3SubnetIngress:        mapEntryDeny,
			mapKeyL3SubnetEgress:         mapEntryDeny,
			mapKeyL3SmallerSubnetIngress: mapEntryDeny,
			mapKeyL3SmallerSubnetEgress:  mapEntryDeny,
		})}, {"deny_part_of_a_subnet_with_an_ip", api.Rules{ruleAllowAllIngress, ruleL3DenySmallerSubnet, ruleL3AllowLargerSubnet}, testMapState(t, mapStateMap{
			mapKeyAnyIngress:             mapEntryAllow,
			mapKeyL3SmallerSubnetIngress: mapEntryDeny,
			mapKeyL3SmallerSubnetEgress:  mapEntryDeny,
			mapKeyL3SubnetIngress:        mapEntryAllow,
			mapKeyL3SubnetEgress:         mapEntryAllow,
		})}, {"broad_cidr_deny_is_a_portproto_subset_of_a_specific_cidr_allow", api.Rules{ruleAllowAllIngress, ruleL3L4Port8080ProtoAnyDenyWorld, ruleL3AllowWorldIP}, testMapState(t, mapStateMap{
			mapKeyAnyIngress:                            mapEntryAllow,
			mapKeyL3L4Port8080ProtoTCPWorldIngress:      mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldEgress:       mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIngress:      mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldEgress:       mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIngress:     mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldEgress:      mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPv4Ingress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPv4Egress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPv4Ingress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPv4Egress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPv4Ingress: mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPv4Egress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPv6Ingress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPv6Egress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPv6Ingress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPv6Egress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPv6Ingress: mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPv6Egress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldSNIngress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldSNEgress:     mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldSNIngress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldSNEgress:     mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldSNIngress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldSNEgress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPIngress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPEgress:     mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPIngress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPEgress:     mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPIngress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPEgress:    mapEntryDeny,
			mapKeyL3SmallerSubnetIngress:                mapEntryAllow,
			mapKeyL3SmallerSubnetEgress:                 mapEntryAllow,
		})}, {"broad_cidr_allow_is_a_portproto_subset_of_a_specific_cidr_deny", api.Rules{ruleAllowAllIngress, ruleL3AllowWorldSubnet, ruleL3DenyWorldIP}, testMapState(t, mapStateMap{
			mapKeyAnyIngress:                          mapEntryAllow,
			mapKeyL3L4Port8080ProtoTCPWorldSNIngress:  mapEntryAllow,
			mapKeyL3L4Port8080ProtoTCPWorldSNEgress:   mapEntryAllow,
			mapKeyL3L4Port8080ProtoUDPWorldSNIngress:  mapEntryAllow,
			mapKeyL3L4Port8080ProtoUDPWorldSNEgress:   mapEntryAllow,
			mapKeyL3L4Port8080ProtoSCTPWorldSNIngress: mapEntryAllow,
			mapKeyL3L4Port8080ProtoSCTPWorldSNEgress:  mapEntryAllow,
			mapKeyL4AnyPortProtoWorldIPIngress:        mapEntryDeny,
			mapKeyL4AnyPortProtoWorldIPEgress:         mapEntryDeny,
		})}, {"named_port_world_subnet", api.Rules{ruleAllowAllIngress, ruleL3AllowWorldSubnetNamedPort}, testMapState(t, mapStateMap{
			mapKeyAnyIngress: mapEntryAllow,
			mapKeyL3L4NamedPortHTTPProtoTCPWorldSubNetIngress: mapEntryAllow,
			mapKeyL3L4NamedPortHTTPProtoTCPWorldIPIngress:     mapEntryAllow,
		})}, {"port_range_world_subnet", api.Rules{ruleAllowAllIngress, ruleL3AllowWorldSubnetPortRange}, testMapState(t, mapStateMap{
			mapKeyAnyIngress: mapEntryAllow,
			mapKeyL3L4Port64To127ProtoTCPWorldSubNetIngress: mapEntryAllow,
			mapKeyL3L4Port5ProtoTCPWorldSubNetIngress:       mapEntryAllow,
			mapKeyL3L4Port6To7ProtoTCPWorldSubNetIngress:    mapEntryAllow,
			mapKeyL3L4Port8To9ProtoTCPWorldSubNetIngress:    mapEntryAllow,
			mapKeyL3L4Port10ProtoTCPWorldSubNetIngress:      mapEntryAllow,
			mapKeyL3L4Port64To127ProtoTCPWorldIPIngress:     mapEntryAllow,
			mapKeyL3L4Port5ProtoTCPWorldIPIngress:           mapEntryAllow,
			mapKeyL3L4Port6To7ProtoTCPWorldIPIngress:        mapEntryAllow,
			mapKeyL3L4Port8To9ProtoTCPWorldIPIngress:        mapEntryAllow,
			mapKeyL3L4Port10ProtoTCPWorldIPIngress:          mapEntryAllow,
		})},
	}
	// Do not test in dualstack mode
	defer func(ipv4, ipv6 bool) {
		option.Config.EnableIPv4 = ipv4
		option.Config.EnableIPv6 = ipv6
	}(option.Config.EnableIPv4, option.Config.EnableIPv6)
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = false
	for _, tt := range tests {
		repo := newPolicyDistillery(t, selectorCache)
		for _, rule := range tt.rules {
			if rule != nil {
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(tt.test, func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal := assert.True(t, mapstate.Equal(&tt.expected), mapstate.diff(&tt.expected)); !equal {
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.test, labelsFoo)
			}
		})
	}
}

var (
	allIPv4         = api.CIDR("0.0.0.0/0")
	lblAllIPv4      = labels.ParseSelectLabelArray(fmt.Sprintf("%s:%s", labels.LabelSourceCIDR, allIPv4))
	one3Z8          = api.CIDR("1.0.0.0/8")
	one3Z8Identity  = localIdentity(16331)
	lblOne3Z8       = labels.ParseSelectLabelArray(fmt.Sprintf("%s:%s", labels.LabelSourceCIDR, one3Z8))
	one0Z32         = api.CIDR("1.1.1.1/32")
	one0Z32Identity = localIdentity(16332)
	lblOne0Z32      = labels.ParseSelectLabelArray(fmt.Sprintf("%s:%s", labels.LabelSourceCIDR, one0Z32))

	ruleAllowEgressDenyCIDRSet = api.NewRule().WithEgressRules([]api.EgressRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: api.CIDRSlice{allIPv4},
		},
	}}).WithEgressDenyRules([]api.EgressDenyRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDRSet: api.CIDRRuleSlice{
				api.CIDRRule{
					Cidr:        one3Z8,
					ExceptCIDRs: []api.CIDR{one0Z32},
				},
			},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)
)

// Allow-ception tests that an allow within a deny within an allow
// is properly calculated.
func Test_Allowception(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)
	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.ReservedIdentityWorld:        append(labels.LabelWorld.LabelArray(), lblAllIPv4...),
		one3Z8Identity:                        lblOne3Z8,  // 16331 (0x3fcb): ["1.0.0.0/8"]
		one0Z32Identity:                       lblOne0Z32, // 16332 (0x3fcc): ["1.1.1.1/32"]
	}
	selectorCache := testNewSelectorCache(hivetest.Logger(t), identityCache)

	computedMapStateForAllowCeption := emptyMapState(hivetest.Logger(t)).withState(mapStateMap{
		ingressKey(0, 0, 0, 0):                             mapEntryL7None_(lblsAllowAllIngress),
		egressKey(identity.ReservedIdentityWorld, 0, 0, 0): mapEntryAllow,
		egressKey(one3Z8Identity, 0, 0, 0):                 mapEntryDeny,
		egressKey(one0Z32Identity, 0, 0, 0):                mapEntryAllow,
	})

	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	// Do not test in dualstack mode
	defer func(ipv4, ipv6 bool) {
		option.Config.EnableIPv4 = ipv4
		option.Config.EnableIPv6 = ipv6
	}(option.Config.EnableIPv4, option.Config.EnableIPv6)
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = false

	repo := newPolicyDistillery(t, selectorCache)
	rules := api.Rules{ruleAllowEgressDenyCIDRSet}
	for _, rule := range rules {
		if rule != nil {
			_, _ = repo.MustAddList(api.Rules{rule})
		}
	}
	logBuffer := new(bytes.Buffer)
	repo = repo.WithLogBuffer(logBuffer)
	mapstate, err := repo.distillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, identity)
	if err != nil {
		t.Errorf("Policy resolution failure: %s", err)
	}
	if equal := assert.True(t, mapstate.Equal(&computedMapStateForAllowCeption), mapstate.diff(&computedMapStateForAllowCeption)); !equal {
		t.Logf("Policy Trace: \n%s\n", logBuffer.String())
		t.Errorf("Policy obtained didn't match expected for endpoint %s", labelsFoo)
	}
}

func Test_EnsureEntitiesSelectableByCIDR(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)
	hostLabel := labels.NewFrom(labels.LabelHost)
	hostLabel.MergeLabels(lblHostIPv4CIDR)
	hostLabel.MergeLabels(lblHostIPv6CIDR)
	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.ReservedIdentityHost:         hostLabel.LabelArray(),
	}
	selectorCache := testNewSelectorCache(hivetest.Logger(t), identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     string
		rules    api.Rules
		expected mapState
	}{
		{"host_cidr_select", api.Rules{ruleL3AllowHostEgress}, emptyMapState(hivetest.Logger(t)).withState(mapStateMap{
			mapKeyL3UnknownIngress: mapEntryL3UnknownIngress,
			mapKeyL3HostEgress:     mapEntryAllow,
		})},
	}

	for _, tt := range tests {
		repo := newPolicyDistillery(t, selectorCache)
		for _, rule := range tt.rules {
			if rule != nil {
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(tt.test, func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal := assert.True(t, mapstate.Equal(&tt.expected), mapstate.diff(&tt.expected)); !equal {
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.test, labelsFoo)
			}
		})
	}
}

func addCIDRIdentity(prefix string, c identity.IdentityMap) identity.NumericIdentity {
	lbls := labels.GetCIDRLabels(netip.MustParsePrefix(prefix)).LabelArray()

	// return an existing id?
	for id, ls := range c {
		if ls.Equals(lbls) {
			return id
		}
	}

	// Find next free id
	id := identity.IdentityScopeLocal
	for {
		if _, exists := c[id]; !exists {
			c[id] = lbls
			return id
		}
		id++
	}
}

func addFQDNIdentity(fqdnSel api.FQDNSelector, c identity.IdentityMap) (id identity.NumericIdentity, adds identity.IdentityMap) {
	lbls := labels.Labels{}
	l := fqdnSel.IdentityLabel()
	lbls[l.Key] = l

	lblA := lbls.LabelArray()

	// return an existing id?
	for id, ls := range c {
		if ls.Equals(lblA) {
			return id, nil
		}
	}

	// Find next free id
	id = identity.IdentityScopeLocal
	for {
		if _, exists := c[id]; !exists {
			return id, identity.IdentityMap{id: lblA}
		}
		id++
	}
}

// Validate that incrementally deleted identities are handled properly when present in both CIDR and FQDN rules.
func Test_IncrementalFQDNDeletion(t *testing.T) {
	logger := hivetest.Logger(t)
	re.InitRegexCompileLRU(logger, defaults.FQDNRegexCompileLRUSize)
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	// load in standard reserved identities
	identityCache := identity.IdentityMap{
		fooIdentity.ID: fooIdentity.LabelArray,
	}
	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		identityCache[ni] = id.Labels.LabelArray()
	})
	id2 := addCIDRIdentity("192.0.2.0/24", identityCache)
	id3 := addCIDRIdentity("192.0.3.0/24", identityCache)
	selectorCache := testNewSelectorCache(logger, identityCache)

	fqdnSel := api.FQDNSelector{MatchName: "www.example.com"}
	idExample, fqdnIdentities := addFQDNIdentity(fqdnSel, identityCache)

	tests := []struct {
		test     string
		rules    api.Rules
		expected MapStateMap
		fqdnIds  identity.IdentityMap
		adds     MapStateMap
	}{{
		test: "incremental_fqdn_deletion",
		rules: api.Rules{
			&api.Rule{
				EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
				Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToCIDR: []api.CIDR{
								"192.0.2.0/24",
								"192.0.3.0/24",
							},
						},
					},
					{
						ToFQDNs: api.FQDNSelectorSlice{fqdnSel},
					},
				},
			},
		},
		expected: MapStateMap{
			mapKeyAllowAll__:     AllowEntry,
			egressL3OnlyKey(id2): AllowEntry,
			egressL3OnlyKey(id3): AllowEntry,
		},
		fqdnIds: maps.Clone(fqdnIdentities),
		adds: MapStateMap{
			egressL3OnlyKey(idExample): AllowEntry,
		},
	}}

	for _, tt := range tests {
		repo := newPolicyDistillery(t, selectorCache)
		repo.MustAddList(tt.rules)

		t.Run(tt.test, func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			epp, err := repo.distillEndpointPolicy(logger, DummyOwner{
				logger: logger,
			}, fooIdentity)
			if err != nil {
				t.Fatal(err)
			}
			mapstate := epp.policyMapState

			if equal := assert.True(t, mapstate.Equals(tt.expected), mapstate.Diff(tt.expected)); !equal {
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.test, labelsFoo)
			}

			wg := &sync.WaitGroup{}
			selectorCache.UpdateIdentities(tt.fqdnIds, nil, wg)
			wg.Wait()

			closer, changes := epp.ConsumeMapChanges()
			adds := MapStateMap{}
			for k := range changes.Adds {
				adds[k] = epp.policyMapState.entries[k].MapStateEntry
			}
			closer()

			if equal := assert.True(t, maps.Equal(adds, tt.adds), adds.Diff(tt.adds)); !equal {
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.test, labelsFoo)
			}

			// let fqdn ID expire
			wg = &sync.WaitGroup{}
			selectorCache.UpdateIdentities(nil, tt.fqdnIds, wg)
			wg.Wait()

			closer, changes = epp.ConsumeMapChanges()
			closer()

			if equal := assert.True(t, epp.policyMapState.Equals(tt.expected), mapstate.Diff(tt.expected)); !equal {
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.test, labelsFoo)
			}

			epp.Ready()
			epp.Detach(logger)
		})
	}
}

func TestEgressPortRangePrecedence(t *testing.T) {
	type portRange struct {
		startPort, endPort uint16
		isAllow            bool
	}
	tests := []struct {
		name       string
		rules      []portRange
		rangeTests []portRange
	}{
		{
			name: "deny range (1-1024) covers port allow (80)",
			rules: []portRange{
				{80, 0, true},
				{1, 1024, false},
			},
			rangeTests: []portRange{
				{79, 81, false},
				{1023, 1025, false},
			},
		},
		{
			name: "deny port (80) in broader allow range (1-1024)",
			rules: []portRange{
				{80, 0, false},
				{1, 1024, true},
			},
			rangeTests: []portRange{
				{1, 2, true},
				{79, 0, true},
				{80, 0, false},
				{81, 0, true},
				{1023, 1024, true},
				{1025, 1026, false},
			},
		},
		{
			name: "wildcard deny (*) covers broad allow range (1-1024)",
			rules: []portRange{
				{0, 0, false},
				{1, 1024, true},
			},
			rangeTests: []portRange{
				{1, 2, false},
				{1023, 1025, false},
			},
		},
		{
			name: "wildcard allow (*) has an deny range hole (1-1024)",
			rules: []portRange{
				{0, 0, true},
				{1, 1024, false},
			},
			rangeTests: []portRange{
				{1, 2, false},
				{1023, 1024, false},
				{1025, 1026, true},
				{65534, 0, true},
			},
		},
		{
			name: "two allow ranges (80-90, 90-100) with overlapping deny (85-95)",
			rules: []portRange{
				{80, 90, true},
				{85, 95, false},
				{90, 100, true},
			},
			rangeTests: []portRange{
				{79, 0, false},
				{80, 84, true},
				{85, 95, false},
				{96, 100, true},
				{101, 0, true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := newTestData(hivetest.Logger(t)).withIDs(ruleTestIDs)
			tr := api.Rule{
				EndpointSelector: endpointSelectorA,
			}
			for _, rul := range tt.rules {
				pp := api.PortProtocol{
					Port:     fmt.Sprintf("%d", rul.startPort),
					EndPort:  int32(rul.endPort),
					Protocol: api.ProtoTCP,
				}
				if rul.isAllow {
					tr.Egress = append(tr.Egress, api.EgressRule{
						EgressCommonRule: api.EgressCommonRule{
							ToEndpoints: []api.EndpointSelector{endpointSelectorB},
						},
						ToPorts: []api.PortRule{{
							Ports: []api.PortProtocol{pp},
						}},
					})
				} else {
					tr.EgressDeny = append(tr.EgressDeny, api.EgressDenyRule{
						EgressCommonRule: api.EgressCommonRule{
							ToEndpoints: []api.EndpointSelector{endpointSelectorB},
						},
						ToPorts: []api.PortDenyRule{{
							Ports: []api.PortProtocol{pp},
						}},
					})
				}
			}
			td.repo.mustAdd(tr)

			flow := flowAToB
			for _, rt := range tt.rangeTests {
				for i := rt.startPort; i <= rt.endPort; i++ {
					flow.Dport = i
					verdict := api.Denied
					if rt.isAllow {
						verdict = api.Allowed
					}
					checkFlow(t, td.repo, flow, verdict)
				}
			}
		})
	}
}
