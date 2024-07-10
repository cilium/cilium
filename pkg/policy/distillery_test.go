// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	ep1 = testutils.NewTestEndpoint()
	ep2 = testutils.NewTestEndpoint()
)

func localIdentity(n uint32) identity.NumericIdentity {
	return identity.NumericIdentity(n) | identity.IdentityScopeLocal

}
func TestCacheManagement(t *testing.T) {
	repo := NewPolicyRepository(nil, nil, nil)
	cache := repo.policyCache
	identity := ep1.GetSecurityIdentity()
	require.Equal(t, identity, ep2.GetSecurityIdentity())

	// Nonsense delete of entry that isn't yet inserted
	deleted := cache.delete(identity)
	require.Equal(t, false, deleted)

	// Insert identity twice. Should be the same policy.
	policy1 := cache.insert(identity)
	policy2 := cache.insert(identity)
	require.Equal(t, policy2, policy1)

	// Despite two insert calls, there is no reference tracking; any delete
	// will clear the cache.
	cacheCleared := cache.delete(identity)
	require.True(t, cacheCleared)
	cacheCleared = cache.delete(identity)
	require.Equal(t, false, cacheCleared)

	// Insert two distinct identities, then delete one. Other should still
	// be there.
	ep3 := testutils.NewTestEndpoint()
	ep3.SetIdentity(1234, true)
	identity3 := ep3.GetSecurityIdentity()
	require.NotEqual(t, identity, identity3)
	policy1 = cache.insert(identity)
	policy3 := cache.insert(identity3)
	require.NotEqual(t, policy3, policy1)
	_ = cache.delete(identity)
	policy3 = cache.lookupOrCreate(identity3, false)
	require.NotNil(t, policy3)
}

func TestCachePopulation(t *testing.T) {
	repo := NewPolicyRepository(nil, nil, nil)
	repo.revision.Store(42)
	cache := repo.policyCache

	identity1 := ep1.GetSecurityIdentity()
	require.Equal(t, identity1, ep2.GetSecurityIdentity())
	policy1 := cache.insert(identity1)

	// Calculate the policy and observe that it's cached
	updated, err := cache.updateSelectorPolicy(identity1)
	require.NoError(t, err)
	require.True(t, updated)
	updated, err = cache.updateSelectorPolicy(identity1)
	require.NoError(t, err)
	require.Equal(t, false, updated)
	policy2 := cache.insert(identity1)
	idp1 := policy1.(*cachedSelectorPolicy).getPolicy()
	idp2 := policy2.(*cachedSelectorPolicy).getPolicy()
	require.Equal(t, idp2, idp1)

	// Remove the identity and observe that it is no longer available
	cacheCleared := cache.delete(identity1)
	require.True(t, cacheCleared)
	updated, err = cache.updateSelectorPolicy(identity1)
	require.Error(t, err)

	// Attempt to update policy for non-cached endpoint and observe failure
	ep3 := testutils.NewTestEndpoint()
	ep3.SetIdentity(1234, true)
	_, err = cache.updateSelectorPolicy(ep3.GetSecurityIdentity())
	require.Error(t, err)
	require.Equal(t, false, updated)

	// Insert endpoint with different identity and observe that the cache
	// is different from ep1, ep2
	policy1 = cache.insert(identity1)
	idp1 = policy1.(*cachedSelectorPolicy).getPolicy()
	require.NotNil(t, idp1)
	identity3 := ep3.GetSecurityIdentity()
	policy3 := cache.insert(identity3)
	require.NotEqual(t, policy1, policy3)
	updated, err = cache.updateSelectorPolicy(identity3)
	require.NoError(t, err)
	require.True(t, updated)
	idp3 := policy3.(*cachedSelectorPolicy).getPolicy()
	require.NotEqual(t, idp1, idp3)

	// If there's an error during policy resolution, update should fail
	//repo.err = fmt.Errorf("not implemented!")
	//repo.revision++
	//_, err = cache.updateSelectorPolicy(identity3)
	//require.Error(t, err)
}

// Distillery integration tests
func key(id uint32, port uint16, hdr uint8, dir uint8) Key {
	mask := uint16(0xffff)
	if port == 0 {
		mask = 0
	}
	return keyWithPortMask(id, port, mask, hdr, dir)
}

// keyWithPortMask returns a key with a specific port mask.
// Note: This method inverts the portMask on the key for the caller.
func keyWithPortMask(id uint32, port, portMask uint16, hdr uint8, dir uint8) Key {
	return types.Key{
		Identity:         id,
		DestPort:         port,
		InvertedPortMask: ^portMask,
		Nexthdr:          hdr,
		TrafficDirection: dir,
	}
}

var (
	// Identity, labels, selectors for an endpoint named "foo"
	identityFoo = uint32(100)
	labelsFoo   = labels.ParseSelectLabelArray("foo", "blue")
	selectFoo_  = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	allowFooL3_ = selectFoo_
	denyFooL3__ = selectFoo_

	// Identity, labels, selectors for an endpoint named "bar"
	identityBar = uint32(200)
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

	// Misc other bpf key fields for convenience / readability.
	dirIngress = trafficdirection.Ingress.Uint8()
	dirEgress  = trafficdirection.Egress.Uint8()
	// Desired map keys for L3, L3-dependent L4, L4
	mapKeyAllowFoo__ = key(identityFoo, 0, 0, dirIngress)
	mapKeyAllowBar__ = key(identityBar, 0, 0, dirIngress)
	mapKeyAllowBarL4 = key(identityBar, 80, 6, dirIngress)
	mapKeyAllowFooL4 = key(identityFoo, 80, 6, dirIngress)
	mapKeyDeny_Foo__ = mapKeyAllowFoo__
	mapKeyDeny_FooL4 = mapKeyAllowFooL4
	mapKeyAllow___L4 = key(0, 80, 6, dirIngress)
	mapKeyDeny____L4 = mapKeyAllow___L4
	mapKeyAllowAll__ = key(0, 0, 0, dirIngress)
	mapKeyAllowAllE_ = key(0, 0, 0, dirEgress)
	// Desired map entries for no L7 redirect / redirect to Proxy
	mapEntryL7None_ = func(lbls ...labels.LabelArray) MapStateEntry {
		return NewMapStateEntry(nil, labels.LabelArrayList(lbls).Sort(), 0, "", 0, false, DefaultAuthType, AuthTypeDisabled).WithOwners()
	}
	mapEntryL7Auth_ = func(at AuthType, lbls ...labels.LabelArray) MapStateEntry {
		return NewMapStateEntry(nil, labels.LabelArrayList(lbls).Sort(), 0, "", 0, false, ExplicitAuthType, at).WithOwners()
	}
	mapEntryL7Deny_ = func(lbls ...labels.LabelArray) MapStateEntry {
		return NewMapStateEntry(nil, labels.LabelArrayList(lbls).Sort(), 0, "", 0, true, DefaultAuthType, AuthTypeDisabled).WithOwners()
	}
	mapEntryL7Proxy = func(lbls ...labels.LabelArray) MapStateEntry {
		entry := NewMapStateEntry(nil, labels.LabelArrayList(lbls).Sort(), 1, "", 0, false, DefaultAuthType, AuthTypeDisabled).WithOwners()
		entry.ProxyPort = 1
		return entry
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

func newPolicyDistillery(selectorCache *SelectorCache) *policyDistillery {
	ret := &policyDistillery{
		Repository: NewPolicyRepository(nil, nil, nil),
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

// distillPolicy distills the policy repository into a set of bpf map state
// entries for an endpoint with the specified labels.
func (d *policyDistillery) distillPolicy(owner PolicyOwner, epLabels labels.LabelArray, identity *identity.Identity) (MapState, error) {
	sp := d.Repository.GetPolicyCache().insert(identity)
	d.Repository.GetPolicyCache().UpdatePolicy(identity)
	epp := sp.Consume(DummyOwner{})
	if epp == nil {
		return nil, errors.New("policy distillation failure")
	}

	// Remove the allow-all egress entry that's generated by default. This is
	// because this test suite doesn't have a notion of traffic direction, so
	// the extra egress allow-all is technically correct, but omitted from the
	// expected output that's asserted against for the sake of brevity.
	epp.policyMapState.Delete(mapKeyAllowAllE_)

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
	assert.Equal(t, res, expected, "invalid permutations")
}

func Test_MergeL3(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
	}
	selectorCache := testNewSelectorCache(identityCache)

	type authResult map[identity.NumericIdentity]AuthTypes
	tests := []struct {
		test   int
		rules  api.Rules
		result MapState
		auths  authResult
	}{
		{
			0,
			api.Rules{ruleL3__AllowFoo, ruleL3__AllowBar},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowBar__: mapEntryL7None_(lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{},
				identity.NumericIdentity(identityFoo): AuthTypes{},
			},
		},
		{
			1,
			api.Rules{ruleL3__AllowFoo, ruleL3L4__Allow},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{},
				identity.NumericIdentity(identityFoo): AuthTypes{},
			},
		},
		{
			2,
			api.Rules{ruleL3__AllowFoo, ruleL3__AllowBarAuth},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{},
			},
		},
		{
			3,
			api.Rules{ruleL3__AllowFoo, ruleL3__AllowBarAuth, rule__L4__AllowAuth},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllow___L4: mapEntryL7Auth_(AuthTypeSpire, lbls__L4__Allow),
				mapKeyAllowFoo__: mapEntryL7None_(lblsL3__AllowFoo),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeAlwaysFail: struct{}{}, AuthTypeSpire: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			4,
			api.Rules{rule____AllowAll, ruleL3__AllowBarAuth},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{},
			},
		},
		{
			5,
			api.Rules{rule____AllowAllAuth, ruleL3__AllowBar},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowAll__: mapEntryL7Auth_(AuthTypeSpire, lbls____AllowAll),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeSpire, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeSpire: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			6,
			api.Rules{rule____AllowAllAuth, rule__L4__Allow},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowAll__: mapEntryL7Auth_(AuthTypeSpire, lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7Auth_(AuthTypeSpire, lbls__L4__Allow),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeSpire: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			7,
			api.Rules{rule____AllowAllAuth, ruleL3__AllowBar, rule__L4__Allow},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowAll__: mapEntryL7Auth_(AuthTypeSpire, lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7Auth_(AuthTypeSpire, lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeSpire, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeSpire: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{AuthTypeSpire: struct{}{}},
			},
		},
		{
			8,
			api.Rules{rule____AllowAll, ruleL3__AllowBar, rule__L4__Allow},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowAll__: mapEntryL7Auth_(AuthTypeDisabled, lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7Auth_(AuthTypeDisabled, lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeDisabled, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{},
				identity.NumericIdentity(identityFoo): AuthTypes{},
			},
		},
		{
			9,
			api.Rules{rule____AllowAll, rule__L4__Allow, ruleL3__AllowBarAuth},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowAll__: mapEntryL7Auth_(AuthTypeDisabled, lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7Auth_(AuthTypeDisabled, lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
				mapKeyAllowBarL4: mapEntryL7Auth_(AuthTypeAlwaysFail, lbls__L4__Allow, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{},
			},
		},
		{
			10, // Same as 9, but the L3L4 entry is created by an explicit rule.
			api.Rules{rule____AllowAll, rule__L4__Allow, ruleL3__AllowBarAuth, ruleL3L4AllowBarAuth},
			NewMapState(map[Key]MapStateEntry{
				mapKeyAllowAll__: mapEntryL7Auth_(AuthTypeDisabled, lbls____AllowAll),
				mapKeyAllow___L4: mapEntryL7Auth_(AuthTypeDisabled, lbls__L4__Allow),
				mapKeyAllowBar__: mapEntryL7Auth_(AuthTypeAlwaysFail, lblsL3__AllowBar),
				mapKeyAllowBarL4: mapEntryL7Auth_(AuthTypeAlwaysFail, lblsL3L4AllowBar, lbls__L4__Allow, lblsL3__AllowBar),
			}),
			authResult{
				identity.NumericIdentity(identityBar): AuthTypes{AuthTypeAlwaysFail: struct{}{}},
				identity.NumericIdentity(identityFoo): AuthTypes{},
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

			repo := newPolicyDistillery(selectorCache)
			_, _ = repo.MustAddList(rules)

			t.Run(fmt.Sprintf("permutation_%d-%d", tt.test, round), func(t *testing.T) {
				logBuffer := new(bytes.Buffer)
				repo = repo.WithLogBuffer(logBuffer)
				mapstate, err := repo.distillPolicy(DummyOwner{}, labelsFoo, identity)
				if err != nil {
					t.Errorf("Policy resolution failure: %s", err)
				}
				if equal := assert.True(t, mapstate.Equals(tt.result), mapstate.Diff(tt.result)); !equal {
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
func testCaseToMapState(t generatedBPFKey) MapState {
	m := newMapState(nil)

	if t.L3Key.L3 != nil {
		if t.L3Key.Deny != nil && *t.L3Key.Deny {
			m.denies.Upsert(mapKeyDeny_Foo__, mapEntryL7Deny_())
		} else {
			// If L7 is not set or if it explicitly set but it's false
			if t.L3Key.L7 == nil || !*t.L3Key.L7 {
				m.allows.Upsert(mapKeyAllowFoo__, mapEntryL7None_())
			}
			// there's no "else" because we don't support L3L7 policies, i.e.,
			// a L4 port needs to be specified.
		}
	}
	if t.L4Key.L3 != nil {
		if t.L4Key.Deny != nil && *t.L4Key.Deny {
			m.denies.Upsert(mapKeyDeny____L4, mapEntryL7Deny_())
		} else {
			// If L7 is not set or if it explicitly set but it's false
			if t.L4Key.L7 == nil || !*t.L4Key.L7 {
				m.allows.Upsert(mapKeyAllow___L4, mapEntryL7None_())
			} else {
				// L7 is set and it's true then we should expected a mapEntry
				// with L7 redirection.
				m.allows.Upsert(mapKeyAllow___L4, mapEntryL7Proxy())
			}
		}
	}
	if t.L3L4Key.L3 != nil {
		if t.L3L4Key.Deny != nil && *t.L3L4Key.Deny {
			m.denies.Upsert(mapKeyDeny_FooL4, mapEntryL7Deny_())
		} else {
			// If L7 is not set or if it explicitly set but it's false
			if t.L3L4Key.L7 == nil || !*t.L3L4Key.L7 {
				m.allows.Upsert(mapKeyAllowFooL4, mapEntryL7None_())
			} else {
				// L7 is set and it's true then we should expected a mapEntry
				// with L7 redirection only if we haven't set it already
				// for an existing L4-only.
				if t.L4Key.L7 == nil || !*t.L4Key.L7 {
					m.allows.Upsert(mapKeyAllowFooL4, mapEntryL7Proxy())
				}
			}
		}
	}

	// Add dependency deny-L3->deny-L3L4 if allow-L4 exists
	denyL3, denyL3exists := m.denies.Lookup(mapKeyDeny_Foo__)
	denyL3L4, denyL3L4exists := m.denies.Lookup(mapKeyDeny_FooL4)
	allowL4, allowL4exists := m.allows.Lookup(mapKeyAllow___L4)
	if allowL4exists && !allowL4.IsDeny && denyL3exists && denyL3.IsDeny && denyL3L4exists && denyL3L4.IsDeny {
		m.AddDependent(mapKeyDeny_Foo__, mapKeyDeny_FooL4, ChangeState{})
	}
	return m
}

func generateMapStates() []MapState {
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
	mapStates := make([]MapState, 0, len(rawTestTable))
	for _, rawTest := range rawTestTable {
		testCase := parseTable(rawTest)
		mapState := testCaseToMapState(testCase)
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
	selectorCache := testNewSelectorCache(identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     int
		rules    api.Rules
		expected MapState
	}{
		// The following table is derived from the Google Doc here:
		// https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw/edit?usp=sharing
		//
		//  Rule 0                   | Rule 1         | Rule 2         | Rule 3         | Rule 4         | Rule 5         | Rule 6         | Rule 7         | Desired BPF map state
		{0, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(nil)},
		{1, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{2, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{3, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{4, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow)})},
		{5, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{6, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},                                                     // identical L3L4 entry suppressed
		{7, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
		{8, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},
		{9, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{10, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},
		{11, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{12, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                      // L3L4 entry suppressed to allow L4-only entry to redirect
		{13, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                  // L3L4 entry suppressed to allow L4-only entry to redirect
		{14, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},                                                     // L3L4 entry suppressed to allow L4-only entry to redirect
		{15, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // L3L4 entry suppressed to allow L4-only entry to redirect
		{16, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow)})},
		{17, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{18, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{19, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{20, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow)})},
		{21, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{22, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{23, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule____NoAllow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{24, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                      // identical L3L4 entry suppressed
		{25, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                  // identical L3L4 entry suppressed
		{26, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},                                                     // identical L3L4 entry suppressed
		{27, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, rule____NoAllow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
		{28, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                      // identical L3L4 entry suppressed
		{29, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                  // identical L3L4 entry suppressed
		{30, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},                                                     // identical L3L4 entry suppressed
		{31, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3L4L7Allow, rule__L4L7Allow, ruleL3L4__Allow, rule__L4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
	}

	expectedMapState := generateMapStates()
	// Add the auto generated test cases for the deny policies
	generatedIdx := 32
	for i := generatedIdx; i < 256; i++ {
		tests = append(tests,
			struct {
				test     int
				rules    api.Rules
				expected MapState
			}{
				test:     i,
				rules:    generateRule(i),
				expected: expectedMapState[i],
			})
	}

	for i, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
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
			mapstate, err := repo.distillPolicy(DummyOwner{}, labelsFoo, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			// Ignore generated rules as they lap LabelArrayList which would
			// make the tests fail.
			if i < generatedIdx {
				if equal := assert.True(t, mapstate.Equals(tt.expected), mapstate.Diff(tt.expected)); !equal {
					require.EqualExportedValuesf(t, tt.expected, mapstate, "Policy obtained didn't match expected for endpoint %s", labelsFoo)
					t.Logf("Rules:\n%s\n\n", tt.rules.String())
					t.Logf("Policy Trace: \n%s\n", logBuffer.String())
					t.Errorf("Policy obtained didn't match expected for endpoint %s", labelsFoo)
				}
			}
			// It is extremely difficult to derive the "DerivedFromRules" field.
			// Since this field is only used for debuggability purposes we can
			// ignore it and test only for the MapState that we are expecting
			// to be plumbed into the datapath.
			mapstate.ForEach(func(k Key, v MapStateEntry) bool {
				if v.DerivedFromRules == nil || len(v.DerivedFromRules) == 0 {
					return true
				}
				v.DerivedFromRules = labels.LabelArrayList(nil).Sort()
				mapstate.Insert(k, v)
				return true
			})
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
	selectorCache := testNewSelectorCache(identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     int
		rules    api.Rules
		expected MapState
	}{
		// The following table is derived from the Google Doc here:
		// https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw/edit?usp=sharing
		//
		//  Rule 0                   | Rule 1         | Rule 2         | Rule 3         | Rule 4         | Rule 5         | Rule 6         | Rule 7         | Desired BPF map state
		{0, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(nil)},
		{1, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{2, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{3, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{4, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow)})},
		{5, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7None_(lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{6, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},                                                     // identical L3L4 entry suppressed
		{7, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
		{8, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},
		{9, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{10, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},
		{11, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{12, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                        // L3L4 entry suppressed to allow L4-only entry to redirect
		{13, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                    // L3L4 entry suppressed to allow L4-only entry to redirect
		{14, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},                                                     // L3L4 entry suppressed to allow L4-only entry to redirect
		{15, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, rule____NoAllow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // L3L4 entry suppressed to allow L4-only entry to redirect
		{16, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow)})},
		{17, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{18, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{19, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{20, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow)})},
		{21, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{22, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow)})},
		{23, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule____NoAllow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllowFooL4: mapEntryL7Proxy(lblsL3L4L7Allow, lblsL3L4__Allow), mapKeyAllow___L4: mapEntryL7None_(lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},
		{24, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                          // identical L3L4 entry suppressed
		{25, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                      // identical L3L4 entry suppressed
		{26, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},                                                       // identical L3L4 entry suppressed
		{27, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, rule____NoAllow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},   // identical L3L4 entry suppressed
		{28, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow)})},                                                                        // identical L3L4 entry suppressed
		{29, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule____NoAllow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})},                    // identical L3L4 entry suppressed
		{30, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, rule____NoAllow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow)})},                                                     // identical L3L4 entry suppressed
		{31, api.Rules{rule_____NoDeny, rule_____NoDeny, rule_____NoDeny, ruleL3npL4L7Allow, rule__npL4L7Allow, ruleL3npL4__Allow, rule__npL4__Allow, ruleL3____Allow}, newMapState(map[Key]MapStateEntry{mapKeyAllow___L4: mapEntryL7Proxy(lbls__L4L7Allow, lbls__L4__Allow), mapKeyAllowFoo__: mapEntryL7None_(lblsL3____Allow)})}, // identical L3L4 entry suppressed
	}
	for _, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(selectFoo_)
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(DummyOwner{}, labelsFoo, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			require.Truef(t, mapstate.Equals(tt.expected),
				"Policy obtained didn't match expected for endpoint %s:\n%s", labelsFoo, mapstate.Diff(tt.expected))
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
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
	}
	selectorCache := testNewSelectorCache(identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     int
		selector api.EndpointSelector
		rules    api.Rules
		expected MapState
	}{
		{0, api.EndpointSelectorNone, api.Rules{rule____AllowAll}, NewMapState(map[Key]MapStateEntry{mapKeyAllowAll__: mapEntryL7None_(lblsAllowAllIngress)})},
		{1, api.WildcardEndpointSelector, api.Rules{rule____AllowAll}, NewMapState(map[Key]MapStateEntry{mapKeyAllowAll__: mapEntryL7None_(lbls____AllowAll)})},
	}

	for _, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
		for _, r := range tt.rules {
			if r != nil {
				rule := r.WithEndpointSelector(tt.selector)
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(fmt.Sprintf("permutation_%d", tt.test), func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(DummyOwner{}, labelsFoo, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal := assert.True(t, mapstate.Equals(tt.expected), mapstate.Diff(tt.expected)); !equal {
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
	worldReservedID           = identity.ReservedIdentityWorld.Uint32()
	mapKeyL3WorldIngress      = key(worldReservedID, 0, 0, trafficdirection.Ingress.Uint8())
	mapKeyL3WorldEgress       = key(worldReservedID, 0, 0, trafficdirection.Egress.Uint8())
	mapEntryDeny              = MapStateEntry{
		ProxyPort:        0,
		DerivedFromRules: labels.LabelArrayList{nil},
		IsDeny:           true,
		owners:           map[MapStateOwner]struct{}{},
	}
	mapEntryAllow = MapStateEntry{
		ProxyPort:        0,
		DerivedFromRules: labels.LabelArrayList{nil},
		owners:           map[MapStateOwner]struct{}{},
	}
	worldLabelArrayList         = labels.LabelArrayList{labels.LabelWorld.LabelArray()}
	mapEntryWorldDenyWithLabels = MapStateEntry{
		ProxyPort:        0,
		DerivedFromRules: worldLabelArrayList,
		IsDeny:           true,
		owners:           map[MapStateOwner]struct{}{},
	}

	worldIPIdentity = localIdentity(16324)
	worldIPCIDR     = api.CIDR("192.0.2.3/32")
	lblWorldIP      = labels.ParseSelectLabelArray(fmt.Sprintf("%s:%s", labels.LabelSourceCIDR, worldIPCIDR))
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
	mapKeyL3SubnetIngress = key(worldSubnetIdentity.Uint32(), 0, 0, trafficdirection.Ingress.Uint8())
	mapKeyL3SubnetEgress  = key(worldSubnetIdentity.Uint32(), 0, 0, trafficdirection.Egress.Uint8())

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

	mapKeyL3WorldIPIngress = key(worldIPIdentity.Uint32(), 0, 0, trafficdirection.Ingress.Uint8())
	mapKeyL3WorldIPEgress  = key(worldIPIdentity.Uint32(), 0, 0, trafficdirection.Egress.Uint8())

	ruleL3AllowHostEgress = api.NewRule().WithEgressRules([]api.EgressRule{{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDRSet: api.CIDRRuleSlice{api.CIDRRule{Cidr: hostIPv4}, api.CIDRRule{Cidr: hostIPv6}},
		},
	}}).WithEndpointSelector(api.WildcardEndpointSelector)

	mapKeyL3UnknownIngress = key(identity.IdentityUnknown.Uint32(), 0, 0, trafficdirection.Ingress.Uint8())
	derivedFrom            = labels.LabelArrayList{
		labels.LabelArray{
			labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyIngress, labels.LabelSourceReserved),
		},
	}
	mapEntryL3UnknownIngress          = NewMapStateEntry(nil, derivedFrom, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled)
	mapKeyL3HostEgress                = key(identity.ReservedIdentityHost.Uint32(), 0, 0, trafficdirection.Egress.Uint8())
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
	mapKeyL3L4Port8080ProtoTCPWorldIngress  = key(worldReservedID, 8080, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoTCPWorldEgress   = key(worldReservedID, 8080, 6, trafficdirection.Egress.Uint8())
	mapKeyL3L4Port8080ProtoUDPWorldIngress  = key(worldReservedID, 8080, 17, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoUDPWorldEgress   = key(worldReservedID, 8080, 17, trafficdirection.Egress.Uint8())
	mapKeyL3L4Port8080ProtoSCTPWorldIngress = key(worldReservedID, 8080, 132, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoSCTPWorldEgress  = key(worldReservedID, 8080, 132, trafficdirection.Egress.Uint8())

	mapKeyL3L4Port8080ProtoTCPWorldSNIngress  = key(worldSubnetIdentity.Uint32(), 8080, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoTCPWorldSNEgress   = key(worldSubnetIdentity.Uint32(), 8080, 6, trafficdirection.Egress.Uint8())
	mapKeyL3L4Port8080ProtoUDPWorldSNIngress  = key(worldSubnetIdentity.Uint32(), 8080, 17, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoUDPWorldSNEgress   = key(worldSubnetIdentity.Uint32(), 8080, 17, trafficdirection.Egress.Uint8())
	mapKeyL3L4Port8080ProtoSCTPWorldSNIngress = key(worldSubnetIdentity.Uint32(), 8080, 132, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoSCTPWorldSNEgress  = key(worldSubnetIdentity.Uint32(), 8080, 132, trafficdirection.Egress.Uint8())

	mapKeyL3L4Port8080ProtoTCPWorldIPIngress  = key(worldIPIdentity.Uint32(), 8080, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoTCPWorldIPEgress   = key(worldIPIdentity.Uint32(), 8080, 6, trafficdirection.Egress.Uint8())
	mapKeyL3L4Port8080ProtoUDPWorldIPIngress  = key(worldIPIdentity.Uint32(), 8080, 17, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoUDPWorldIPEgress   = key(worldIPIdentity.Uint32(), 8080, 17, trafficdirection.Egress.Uint8())
	mapKeyL3L4Port8080ProtoSCTPWorldIPIngress = key(worldIPIdentity.Uint32(), 8080, 132, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8080ProtoSCTPWorldIPEgress  = key(worldIPIdentity.Uint32(), 8080, 132, trafficdirection.Egress.Uint8())

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
	mapKeyAnyIngress                        = key(0, 0, 0, trafficdirection.Ingress.Uint8())
	mapKeyL4AnyPortProtoWorldIPIngress      = key(worldIPIdentity.Uint32(), 0, 0, trafficdirection.Ingress.Uint8())
	mapKeyL4AnyPortProtoWorldIPEgress       = key(worldIPIdentity.Uint32(), 0, 0, trafficdirection.Egress.Uint8())
	mapKeyL4Port8080ProtoTCPWorldIPIngress  = key(worldIPIdentity.Uint32(), 8080, 6, trafficdirection.Ingress.Uint8())
	mapKeyL4Port8080ProtoTCPWorldIPEgress   = key(worldIPIdentity.Uint32(), 8080, 6, trafficdirection.Egress.Uint8())
	mapKeyL4Port8080ProtoUDPWorldIPIngress  = key(worldIPIdentity.Uint32(), 8080, 17, trafficdirection.Ingress.Uint8())
	mapKeyL4Port8080ProtoUDPWorldIPEgress   = key(worldIPIdentity.Uint32(), 8080, 17, trafficdirection.Egress.Uint8())
	mapKeyL4Port8080ProtoSCTPWorldIPIngress = key(worldIPIdentity.Uint32(), 8080, 132, trafficdirection.Ingress.Uint8())
	mapKeyL4Port8080ProtoSCTPWorldIPEgress  = key(worldIPIdentity.Uint32(), 8080, 132, trafficdirection.Egress.Uint8())
	mapEntryL4WorldIPDependentsIngressDeny  = MapStateEntry{
		ProxyPort:        0,
		IsDeny:           true,
		DerivedFromRules: labels.LabelArrayList{nil},
		owners:           map[MapStateOwner]struct{}{},
		dependents: Keys{
			mapKeyL4Port8080ProtoTCPWorldIPIngress:  struct{}{},
			mapKeyL4Port8080ProtoUDPWorldIPIngress:  struct{}{},
			mapKeyL4Port8080ProtoSCTPWorldIPIngress: struct{}{},
		},
	}
	mapEntryL4WorldIPDependentsEgressDeny = MapStateEntry{
		ProxyPort:        0,
		IsDeny:           true,
		DerivedFromRules: labels.LabelArrayList{nil},
		owners:           map[MapStateOwner]struct{}{},
		dependents: Keys{
			mapKeyL4Port8080ProtoTCPWorldIPEgress:  struct{}{},
			mapKeyL4Port8080ProtoUDPWorldIPEgress:  struct{}{},
			mapKeyL4Port8080ProtoSCTPWorldIPEgress: struct{}{},
		},
	}

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
	mapKeyL3L4NamedPortHTTPProtoTCPWorldSubNetIngress = key(worldSubnetIdentity.Uint32(), 80, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4NamedPortHTTPProtoTCPWorldIPIngress     = key(worldIPIdentity.Uint32(), 80, 6, trafficdirection.Ingress.Uint8())

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
	mapKeyL3L4Port64To127ProtoTCPWorldSubNetIngress = keyWithPortMask(worldSubnetIdentity.Uint32(), 64, 0xffc0, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port5ProtoTCPWorldSubNetIngress       = key(worldSubnetIdentity.Uint32(), 5, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port6To7ProtoTCPWorldSubNetIngress    = keyWithPortMask(worldSubnetIdentity.Uint32(), 6, 0xfffe, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8To9ProtoTCPWorldSubNetIngress    = keyWithPortMask(worldSubnetIdentity.Uint32(), 8, 0xfffe, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port10ProtoTCPWorldSubNetIngress      = key(worldSubnetIdentity.Uint32(), 10, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port64To127ProtoTCPWorldIPIngress     = keyWithPortMask(worldIPIdentity.Uint32(), 64, 0xffc0, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port5ProtoTCPWorldIPIngress           = key(worldIPIdentity.Uint32(), 5, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port6To7ProtoTCPWorldIPIngress        = keyWithPortMask(worldIPIdentity.Uint32(), 6, 0xfffe, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port8To9ProtoTCPWorldIPIngress        = keyWithPortMask(worldIPIdentity.Uint32(), 8, 0xfffe, 6, trafficdirection.Ingress.Uint8())
	mapKeyL3L4Port10ProtoTCPWorldIPIngress          = key(worldIPIdentity.Uint32(), 10, 6, trafficdirection.Ingress.Uint8())
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
		worldIPIdentity:                       lblWorldIP,                  // "192.0.2.3/32"
		worldSubnetIdentity:                   lblWorldSubnet.LabelArray(), // "192.0.2.0/24"
	}
	selectorCache := testNewSelectorCache(identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     string
		rules    api.Rules
		expected MapState
	}{
		{"deny_world_no_labels", api.Rules{ruleAllowAllIngress, ruleL3DenyWorld, ruleL3AllowWorldIP}, newMapState(map[Key]MapStateEntry{
			mapKeyAnyIngress:       mapEntryAllow,
			mapKeyL3WorldIngress:   mapEntryDeny,
			mapKeyL3WorldEgress:    mapEntryDeny,
			mapKeyL3SubnetIngress:  mapEntryDeny,
			mapKeyL3SubnetEgress:   mapEntryDeny,
			mapKeyL3WorldIPIngress: mapEntryDeny,
			mapKeyL3WorldIPEgress:  mapEntryDeny,
		})}, {"deny_world_with_labels", api.Rules{ruleAllowAllIngress, ruleL3DenyWorldWithLabels, ruleL3AllowWorldIP}, newMapState(map[Key]MapStateEntry{
			mapKeyAnyIngress:       mapEntryAllow,
			mapKeyL3WorldIngress:   mapEntryWorldDenyWithLabels,
			mapKeyL3WorldEgress:    mapEntryWorldDenyWithLabels,
			mapKeyL3SubnetIngress:  mapEntryDeny,
			mapKeyL3SubnetEgress:   mapEntryDeny,
			mapKeyL3WorldIPIngress: mapEntryDeny,
			mapKeyL3WorldIPEgress:  mapEntryDeny,
		})}, {"deny_one_ip_with_a_larger_subnet", api.Rules{ruleAllowAllIngress, ruleL3DenySubnet, ruleL3AllowWorldIP}, newMapState(map[Key]MapStateEntry{
			mapKeyAnyIngress:       mapEntryAllow,
			mapKeyL3SubnetIngress:  mapEntryDeny,
			mapKeyL3SubnetEgress:   mapEntryDeny,
			mapKeyL3WorldIPIngress: mapEntryDeny,
			mapKeyL3WorldIPEgress:  mapEntryDeny,
		})}, {"deny_part_of_a_subnet_with_an_ip", api.Rules{ruleAllowAllIngress, ruleL3DenySmallerSubnet, ruleL3AllowLargerSubnet}, newMapState(map[Key]MapStateEntry{
			mapKeyAnyIngress:       mapEntryAllow,
			mapKeyL3WorldIPIngress: mapEntryDeny,
			mapKeyL3WorldIPEgress:  mapEntryDeny,
			mapKeyL3SubnetIngress:  mapEntryAllow,
			mapKeyL3SubnetEgress:   mapEntryAllow,
		})}, {"broad_cidr_deny_is_a_portproto_subset_of_a_specific_cidr_allow", api.Rules{ruleAllowAllIngress, ruleL3L4Port8080ProtoAnyDenyWorld, ruleL3AllowWorldIP}, newMapState(map[Key]MapStateEntry{
			mapKeyAnyIngress:                          mapEntryAllow,
			mapKeyL3L4Port8080ProtoTCPWorldIngress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldEgress:     mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIngress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldEgress:     mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIngress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldEgress:    mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldSNIngress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldSNEgress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldSNIngress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldSNEgress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldSNIngress: mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldSNEgress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPIngress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoTCPWorldIPEgress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPIngress:  mapEntryDeny,
			mapKeyL3L4Port8080ProtoUDPWorldIPEgress:   mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPIngress: mapEntryDeny,
			mapKeyL3L4Port8080ProtoSCTPWorldIPEgress:  mapEntryDeny,
			mapKeyL3WorldIPIngress:                    mapEntryAllow,
			mapKeyL3WorldIPEgress:                     mapEntryAllow,
		})}, {"broad_cidr_allow_is_a_portproto_subset_of_a_specific_cidr_deny", api.Rules{ruleAllowAllIngress, ruleL3AllowWorldSubnet, ruleL3DenyWorldIP}, newMapState(map[Key]MapStateEntry{
			mapKeyAnyIngress:                          mapEntryAllow,
			mapKeyL3L4Port8080ProtoTCPWorldSNIngress:  mapEntryAllow,
			mapKeyL3L4Port8080ProtoTCPWorldSNEgress:   mapEntryAllow,
			mapKeyL3L4Port8080ProtoUDPWorldSNIngress:  mapEntryAllow,
			mapKeyL3L4Port8080ProtoUDPWorldSNEgress:   mapEntryAllow,
			mapKeyL3L4Port8080ProtoSCTPWorldSNIngress: mapEntryAllow,
			mapKeyL3L4Port8080ProtoSCTPWorldSNEgress:  mapEntryAllow,
			mapKeyL4AnyPortProtoWorldIPIngress:        mapEntryL4WorldIPDependentsIngressDeny,
			mapKeyL4AnyPortProtoWorldIPEgress:         mapEntryL4WorldIPDependentsEgressDeny,
			mapKeyL4Port8080ProtoTCPWorldIPIngress:    mapEntryDeny,
			mapKeyL4Port8080ProtoTCPWorldIPEgress:     mapEntryDeny,
			mapKeyL4Port8080ProtoUDPWorldIPIngress:    mapEntryDeny,
			mapKeyL4Port8080ProtoUDPWorldIPEgress:     mapEntryDeny,
			mapKeyL4Port8080ProtoSCTPWorldIPIngress:   mapEntryDeny,
			mapKeyL4Port8080ProtoSCTPWorldIPEgress:    mapEntryDeny,
		})}, {"named_port_world_subnet", api.Rules{ruleAllowAllIngress, ruleL3AllowWorldSubnetNamedPort}, newMapState(map[Key]MapStateEntry{
			mapKeyAnyIngress: mapEntryAllow,
			mapKeyL3L4NamedPortHTTPProtoTCPWorldSubNetIngress: mapEntryAllow,
			mapKeyL3L4NamedPortHTTPProtoTCPWorldIPIngress:     mapEntryAllow,
		})}, {"port_range_world_subnet", api.Rules{ruleAllowAllIngress, ruleL3AllowWorldSubnetPortRange}, newMapState(map[Key]MapStateEntry{
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
		repo := newPolicyDistillery(selectorCache)
		for _, rule := range tt.rules {
			if rule != nil {
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(tt.test, func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(DummyOwner{}, labelsFoo, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal := assert.True(t, mapstate.Equals(tt.expected), mapstate.Diff(tt.expected)); !equal {
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.test, labelsFoo)
			}
		})
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
	selectorCache := testNewSelectorCache(identityCache)
	identity := identity.NewIdentityFromLabelArray(identity.NumericIdentity(identityFoo), labelsFoo)

	tests := []struct {
		test     string
		rules    api.Rules
		expected MapState
	}{
		{"host_cidr_select", api.Rules{ruleL3AllowHostEgress}, newMapState(map[Key]MapStateEntry{
			mapKeyL3UnknownIngress: mapEntryL3UnknownIngress,
			mapKeyL3HostEgress:     mapEntryAllow,
		})},
	}

	for _, tt := range tests {
		repo := newPolicyDistillery(selectorCache)
		for _, rule := range tt.rules {
			if rule != nil {
				_, _ = repo.MustAddList(api.Rules{rule})
			}
		}
		t.Run(tt.test, func(t *testing.T) {
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			mapstate, err := repo.distillPolicy(DummyOwner{}, labelsFoo, identity)
			if err != nil {
				t.Errorf("Policy resolution failure: %s", err)
			}
			if equal := assert.True(t, mapstate.Equals(tt.expected), mapstate.Diff(tt.expected)); !equal {
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.test, labelsFoo)
			}
		})
	}
}
