// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapState_AccumulateMapChanges_Ordered(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}

	logger := hivetest.Logger(t)
	selectorCache := testNewSelectorCache(t, logger, identityCache)

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    u8proto.U8proto
		ingress  bool
		redirect bool
		deny     bool
		authReq  AuthRequirement
		level    types.Priority
	}
	tests := []struct {
		name  string
		args  []args // changes applied, in order
		state mapState
	}{
		// These tests attempt to cover the four cases in InsertWithChanges
		{
			name: "test-order-1a - do not insert lower-prio longer-match keys under shorter-match keys",
			args: []args{
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: false},
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: true},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): allowEntry().withLevel(1),
			}),
		}, {
			name: "test-order-1b - do not insert unnecessary deny keys, same level",
			args: []args{
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: true},
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: true},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): denyEntry().withLevel(2),
			}),
		}, {
			name: "test-order-2a - delete lower-prio longer-match keys",
			args: []args{
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: true},
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: true},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): denyEntry().withLevel(1),
			}),
		}, {
			name: "test-order-2b - delete lower-prio longer-match allow keys",
			args: []args{
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: false},
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: true},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): denyEntry().withLevel(1),
			}),
		}, {
			name: "test-order-2c - delete longer-match same-prio redundant deny keys",
			args: []args{
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: true},
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: true},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): denyEntry().withLevel(1),
			}),
		}, {
			name: "test-order-3a - do not insert a longer-match key if would cover a shorter-match key of higher level",
			args: []args{
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: false},
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: false},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): allowEntry().withLevel(1),
			}),
		},
		{
			name: "test-order-3b - do not insert a longer-match key if would cover a shorter-match key of higher level",
			args: []args{
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: true},
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: false},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): denyEntry().withLevel(1),
			}),
		},
		{
			name: "test-order-4a - delete covered entries of lower level",
			args: []args{
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: false},
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: false},
			},
			state: testMapState(t, mapStateMap{
				TcpEgressKey(44): allowEntry().withLevel(1),
			}),
		},
		{
			name: "test-order-5a - pull auth down from same level",
			args: []args{
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 0, authReq: types.AuthTypeSpire.AsExplicitRequirement(), ingress: false, redirect: false, deny: false},
				{level: 2, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, redirect: false, deny: false},
				{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: false, deny: false},
			},
			state: testMapState(t, mapStateMap{
				EgressKey().WithIdentity(44): allowEntry().withExplicitAuth(AuthTypeSpire).withLevel(2),
				TcpEgressKey(44):             allowEntry().withDerivedAuth(AuthTypeSpire).withLevel(2),
				HttpEgressKey(44):            allowEntry().withLevel(1),
			}),
		},
	}

	epPolicy := &EndpointPolicy{
		SelectorPolicy: &selectorPolicy{
			SelectorCache: selectorCache,
		},
		PolicyOwner: DummyOwner{logger: hivetest.Logger(t)},
	}

	for _, tt := range tests {
		t.Log(tt.name)
		policyMaps := MapChanges{logger: logger}
		policyMapState := emptyMapState(logger)
		epPolicy.policyMapState = policyMapState

		for _, x := range tt.args {
			dir := trafficdirection.Egress
			if x.ingress {
				dir = trafficdirection.Ingress
			}
			adds := x.cs.addSelections(x.adds...)
			deletes := x.cs.deleteSelections(x.deletes...)
			key := KeyForDirection(dir).WithPortProto(x.proto, x.port)
			var proxyPort uint16
			if x.redirect {
				proxyPort = 1
			}
			verdict := types.Allow
			if x.deny {
				verdict = types.Deny
			}
			value := newMapStateEntry(x.level, types.MaxPriority, NilRuleOrigin, proxyPort, 0, verdict, x.authReq)
			policyMaps.AccumulateMapChanges(0, 0, adds, deletes, []Key{key}, value)
		}
		policyMaps.SyncMapChanges(types.MockSelectorSnapshot())
		policyMaps.consumeMapChanges(epPolicy, allFeatures)
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equal(&tt.state), "%s (MapState):\n%s", tt.name, policyMapState.diff(&tt.state))
	}
}

var (
	port80 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", EndPort: 0, Protocol: api.ProtoTCP},
		},
	}}

	port80_81 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", EndPort: 81, Protocol: api.ProtoTCP},
		},
	}}

	port80_90 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", EndPort: 90, Protocol: api.ProtoTCP},
		},
	}}

	portUDP53 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "53", Protocol: api.ProtoUDP},
		},
	}}

	portTCPAll = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "0", Protocol: api.ProtoTCP},
		},
	}}
)

func TestOrderedPolicyValidation(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)
	logger := hivetest.Logger(t)

	// identities used in tests
	identityWorld := identity.ReservedIdentityWorld
	identityWorldIPv4 := identity.ReservedIdentityWorldIPv4
	identityWorldIPv6 := identity.ReservedIdentityWorldIPv6
	labelsWorld := labels.LabelWorld.LabelArray()

	identity1111 := localIdentity(1111)
	labels1111 := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("1.1.1.1/32")))).LabelArray()
	selector1111 := types.ToSelector(api.CIDR("1.1.1.1/32"))
	selectors1111 := types.Selectors{selector1111}

	identity1100 := localIdentity(1100)
	labels1100 := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("1.1.0.0/16")))).LabelArray()
	selector1100 := types.ToSelector(api.CIDR("1.1.0.0/16"))
	selectors1100 := types.Selectors{selector1100}

	wildcardSubject := types.NewLabelSelector(api.WildcardEndpointSelector)

	AllowEntry := types.AllowEntry()
	allowEntry := NewMapStateEntry(AllowEntry).withLabels(labels.LabelArrayList{nil})
	DenyEntry := types.DenyEntry()
	denyEntry := NewMapStateEntry(DenyEntry).withLabels(labels.LabelArrayList{nil})
	passEntry := PassEntry(0, types.MaxPriority, NilRuleOrigin).withLabels(labels.LabelArrayList{nil})

	identityCache := identity.IdentityMap{
		identityFoo:       labelsFoo,
		identityWorld:     labelsWorld,
		identityWorldIPv4: labels.LabelWorldIPv4.LabelArray(),
		identityWorldIPv6: labels.LabelWorldIPv6.LabelArray(),
		identity1111:      labels1111,
		identity1100:      labels1100,
	}
	selectorCache := testNewSelectorCache(t, logger, identityCache)
	identity := identity.NewIdentityFromLabelArray(identityFoo, labelsFoo)

	type probe struct {
		key   Key
		found bool
		entry MapStateEntry
	}

	tests := []struct {
		name            string                // test name
		skipDefaultDeny bool                  // skip setting DefaultDeny on 'entries'
		entries         types.PolicyEntries   // starts at level 1, level increments for each rule
		expected        map[Key]mapStateEntry // expected MapState, optional
		probes          []probe               // probes to test the policy, optional
	}{
		{
			name: "allow all",
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:      types.ToSelectors(api.WildcardEndpointSelector),
					Verdict: types.Allow,
				},
			},
			expected: mapStateMap{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				egressKey(0, 0, 0, 0):  allowEntry.withLevel(0),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 82, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "allow TCP 80",
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:      types.Selectors{},
					L4:      port80,
					Verdict: types.Allow,
				},
			},
			expected: mapStateMap{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				egressKey(0, 6, 80, 0): allowEntry.withLevel(0),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "allow 1.1.1.1 deny port 80",
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					Tier:     0,
					Priority: 0,
					L3:       types.Selectors{},
					L4:       port80,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					Tier:     1,
					Priority: 0,
					L3:       selectors1111,
					L4:       port80_81,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					Tier:     1,
					Priority: 1,
					L3:       types.ToSelectors(api.WildcardEndpointSelector),
					Verdict:  types.Allow,
				},
			},
			expected: mapStateMap{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),

				egressKey(0, 6, 80, 0):             denyEntry.withLevel(0),
				egressKey(identity1111, 6, 81, 15): allowEntry.withLevel(1000),
				egressKey(0, 0, 0, 0):              allowEntry.withLevel(1001),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
				{key: egressKey(identityWorld, 6, 82, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "PASS 1.1.1.1 over deny, allow shadowing PASS",
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					Tier:     0,
					Priority: 0,
					L3:       selectors1111,
					Verdict:  types.Pass,
				},
				&types.PolicyEntry{
					Tier:     0,
					Priority: 1,
					L3:       types.ToSelectors(api.WildcardEndpointSelector),
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					Tier:     1,
					Priority: 1,
					L3:       selectors1111,
					Verdict:  types.Allow,
				},
			},
			expected: mapStateMap{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),

				egressKey(0, 0, 0, 0):            denyEntry.withLevel(11),
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(1).withPassPriority(0, 1000),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
				{key: egressKey(identityWorld, 6, 82, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "PASS 1.1.1.1 over deny, allows shadowing PASS",
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					Tier:     0,
					Priority: 0,
					L3:       selectors1100,
					Verdict:  types.Pass,
				},
				&types.PolicyEntry{
					Tier:     0,
					Priority: 1,
					L3:       types.Selectors{},
					L4:       port80,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					Tier:     1, // -> 1000, but covered by PASS -> 0
					Priority: 0,
					L3:       selectors1111,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					Tier:     1, // 1001, but covered by both PASS and allow
					Priority: 1,
					L3:       selectors1100,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					Tier:     2, // -> 2000
					Priority: 0,
					L3:       types.ToSelectors(api.WildcardEndpointSelector),
					Verdict:  types.Deny,
				},
			},
			expected: mapStateMap{
				// default allow ingress
				ingressKey(0, 0, 0, 0):           newAllowEntryWithLabels(LabelsAllowAnyIngress),
				egressKey(0, 6, 80, 0):           denyEntry.withLevel(11),
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(1).withPassPriority(0, 1000),
				egressKey(identity1100, 0, 0, 0): denyEntry.withLevel(2).withPassPriority(0, 1000),
				egressKey(0, 0, 0, 0):            denyEntry.withLevel(2000),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				//{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
				//{key: egressKey(identityWorld, 6, 82, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "PASS 1.1.1.1 over deny",
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					Tier:     0,
					Priority: 0,
					L3:       selectors1111,
					Verdict:  types.Pass,
				},
				&types.PolicyEntry{
					Tier:     0,
					Priority: 1,
					L3:       selectors1111,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					Tier:     1,
					Priority: 0,
					L3:       selectors1111,
					L4:       port80,
					Verdict:  types.Allow,
				},
			},
			expected: mapStateMap{
				// default allow ingress
				ingressKey(0, 0, 0, 0):            newAllowEntryWithLabels(LabelsAllowAnyIngress),
				egressKey(identity1111, 0, 0, 0):  passEntry.withPassPriority(0, 1000),
				egressKey(identity1111, 6, 80, 0): allowEntry.withLevel(1),
			},
			probes: []probe{},
		}, {
			name:            "PASS 1.1.1.1 over deny with default allow",
			skipDefaultDeny: true,
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					Tier:     0,
					Priority: 0,
					L3:       selectors1111,
					Verdict:  types.Pass,
				},
				&types.PolicyEntry{
					Tier:     0,
					Priority: 1,
					L3:       selectors1111,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					Tier:     1,
					Priority: 0,
					L3:       selectors1111,
					L4:       port80,
					Verdict:  types.Allow,
				},
			},
			expected: mapStateMap{
				// default allow ingress
				ingressKey(0, 0, 0, 0):            newAllowEntryWithLabels(LabelsAllowAnyIngress),
				egressKey(identity1111, 0, 0, 0):  passEntry.withPassPriority(0, 1000),
				egressKey(identity1111, 6, 80, 0): allowEntry.withLevel(1),
				// default allow egress
				egressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyEgress).withLevel(2000),
			},
			probes: []probe{},
		}, {
			name: "allow 1.1.1.1, deny 1.1.1.1",
			// 0: allow 1.1.1.1
			// 0: deny 1.1.1.1
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 0,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 0,
					Verdict:  types.Deny,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// deny 1111
				egressKey(identity1111, 0, 0, 0): denyEntry.withLevel(0),
			},
			probes: []probe{
				//{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: DenyEntry},
			},
		},

		{
			name: "allow 1.1.1.1, deny 1.1.1.1 (override)",
			// -1. allow 1.1.1.1
			// 1. deny 1.1.1.1
			entries: types.PolicyEntries{
				// allow 1.1.1.1/32
				// this would ordinarily get overridden
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: -1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 1,
					Verdict:  types.Deny,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// allow entries due to rule 1
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(0),
			},
			probes: []probe{
				//{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "allow 1.1.1.1:80, deny 1.1.1.1",
			// 0. allow 1.1.1.1:80
			// 1. deny 1.1.1.1
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					L4:       port80,
					Priority: 0,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 1,
					Verdict:  types.Deny,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// deny 1111
				egressKey(identity1111, 0, 0, 0): denyEntry.withLevel(1),
				// allow 1111:80
				egressKey(identity1111, 6, 80, 16): allowEntry.withLevel(0),
			},
			probes: []probe{
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: DenyEntry},
			},
		}, {
			name: "allow one.one.one.one, deny everything else on port 80 TAKE 1",
			// 0. allow 1.1.1.1
			// 1. deny *:80
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 0,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80,
					Priority: 1,
					Verdict:  types.Deny,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// allow entries due to rule 1
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(0),
				// deny entries for rule 2
				egressKey(0, 6, 80, 16): denyEntry.withLevel(1),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1100, 6, 82, 16), found: false, entry: DenyEntry},
			},
		}, {
			name: "allow one.one.one.one, deny everything else on port 80 TAKE 2",
			// -1. allow 1.1.1.1:80
			// 0. deny *:80-81
			// 0. allow 1.1.1.1:*
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					L4:       port80,
					Priority: -1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80_81,
					Priority: 0,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 0,
					Verdict:  types.Allow,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// allow entries for rule 1
				egressKey(identity1111, 6, 80, 16): allowEntry.withLevel(0),
				// deny entries for rule 2
				egressKey(0, 6, 80, 15): denyEntry.withLevel(1),
				// allow entries for rule 3
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(1),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "allow one.one.one.one, deny everything else on port 80 TAKE 3",
			// 1: allow 1.1.1.1:80-81
			// 2: deny *:80
			// 3: allow 1.1.1.1:*
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					L4:       port80_81,
					Priority: 1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80,
					Priority: 2,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 3,
					Verdict:  types.Allow,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// allow entries for level 1
				egressKey(identity1111, 6, 80, 15): allowEntry.withLevel(0),
				// deny entries for level 2
				egressKey(0, 6, 80, 16): denyEntry.withLevel(1),
				// allow entries due to level 3
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(2),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "allow one.one.one.one, deny everything else on port 80 TAKE 4",
			// 1: allow 1.1.1.1:80-81
			// 2: deny *:80-90
			// 3: allow 1.1.1.1:*
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					L4:       port80_81,
					Priority: 1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80_90,
					Priority: 2,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 3,
					Verdict:  types.Allow,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// allow entries for level 1
				egressKey(identity1111, 6, 80, 15): allowEntry.withLevel(0),
				// deny entries for level 2
				egressKey(0, 6, 80, 13): denyEntry.withLevel(1),
				egressKey(0, 6, 88, 15): denyEntry.withLevel(1),
				egressKey(0, 6, 90, 16): denyEntry.withLevel(1),
				// allow entries due to level 3
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(2),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 90, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 91, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 8080, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "allow one.one.one.one:80-81, deny everything else on ports 80-81, then allow on 1.1.1.1:*",
			// 1: allow 1.1.1.1:80-81
			// 2: deny *:80-81
			// 3: allow 1.1.1.1:*
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					L4:       port80_81,
					Priority: 1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80_81,
					Priority: 2,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					L3:       selectors1111,
					Priority: 3,
					Verdict:  types.Allow,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// allow entries for line 0
				egressKey(identity1111, 6, 80, 15): allowEntry.withLevel(0),
				// deny entries for line 1
				egressKey(0, 6, 80, 15): denyEntry.withLevel(1),
				// allow entries due to line 2
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(2),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 8080, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "allow one.one.one.one, deny everything else on port 80",
			// 1: allow 1.1.1.1:80
			// 2: deny *:80-81
			// 3: allow 1.1.0.0/16:*
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					L4:       port80,
					Priority: 1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80_81,
					Priority: 2,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					L3:       selectors1100,
					Priority: 3,
					Verdict:  types.Allow,
				},
			},
			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0): newAllowEntryWithLabels(LabelsAllowAnyIngress),
				// allow entries for rule 1
				egressKey(identity1111, 6, 80, 0): allowEntry.withLevel(0),
				// deny entries for rule 2
				egressKey(0, 6, 80, 15): denyEntry.withLevel(1),
				// allow entries due rule 3
				egressKey(identity1100, 0, 0, 0): allowEntry.withLevel(2),
				egressKey(identity1111, 0, 0, 0): allowEntry.withLevel(2),
			},
			probes: []probe{
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 81, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 6, 8080, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1100, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 6, 81, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 6, 82, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1100, 6, 8080, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "ordered test-1a: earlier order allow takes precedence",
			// 1: allow foo:80-81
			// 2: deny *:80
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       types.ToSelectors(types.APISelector(selectFoo_)),
					L4:       port80_81,
					Ingress:  true,
					Priority: 1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80,
					Priority: 2,
					Ingress:  true,
					Verdict:  types.Deny,
				},
			},
			expected: map[Key]mapStateEntry{
				ingressKey(identityFoo, 6, 80, 15): allowEntry.withLevel(0),
				ingressKey(0, 6, 80, 16):           denyEntry.withLevel(1),
				egressKey(0, 0, 0, 0):              newAllowEntryWithLabels(LabelsAllowAnyEgress),
			},
			probes: []probe{
				{key: ingressKey(identityWorld, 17, 8080, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 8080, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 79, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 81, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 82, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityFoo, 17, 8080, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityFoo, 6, 8080, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityFoo, 6, 79, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityFoo, 6, 80, 16), found: true, entry: AllowEntry},
				{key: ingressKey(identityFoo, 6, 81, 16), found: true, entry: AllowEntry},
				{key: ingressKey(identityFoo, 6, 82, 16), found: false, entry: DenyEntry},
			},
		}, {
			name: "ordered test-1b: earlier order allow takes precedence",
			// 1: allow foo:*
			// 2: deny *:80
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       types.ToSelectors(types.APISelector(selectFoo_)),
					Ingress:  true,
					Priority: 1,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       port80,
					Priority: 2,
					Ingress:  true,
					Verdict:  types.Deny,
				},
			},
			expected: map[Key]mapStateEntry{
				ingressL3OnlyKey(identityFoo): allowEntry.withLevel(0),
				ingressKey(0, 6, 80, 0):       denyEntry.withLevel(1),
				egressKey(0, 0, 0, 0):         newAllowEntryWithLabels(LabelsAllowAnyEgress),
			},
			probes: []probe{
				{key: ingressKey(identityWorld, 17, 8080, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 8080, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: ingressKey(identityFoo, 17, 8080, 16), found: true, entry: AllowEntry},
				{key: ingressKey(identityFoo, 6, 8080, 16), found: true, entry: AllowEntry},
				{key: ingressKey(identityFoo, 6, 80, 16), found: true, entry: AllowEntry},
			},
		}, {
			name: "ordered test-2a: earlier order deny takes precedence",
			// 1: deny foo
			// 2: allow *:(tcp)
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       types.ToSelectors(types.APISelector(selectFoo_)),
					Ingress:  true,
					Priority: 1,
					Verdict:  types.Deny,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					L4:       portTCPAll,
					Priority: 2,
					Ingress:  true,
					Verdict:  types.Allow,
				},
			},
			expected: map[Key]mapStateEntry{
				ingressL3OnlyKey(identityFoo): denyEntry.withLevel(0),
				ingressKey(0, 6, 0, 0):        allowEntry.withLevel(1),
				egressKey(0, 0, 0, 0):         newAllowEntryWithLabels(LabelsAllowAnyEgress),
			},
			probes: []probe{
				{key: ingressKey(identityWorld, 17, 8080, 16), found: false, entry: DenyEntry},
				{key: ingressKey(identityWorld, 6, 8080, 16), found: true, entry: AllowEntry},
				{key: ingressKey(identityWorld, 6, 80, 16), found: true, entry: AllowEntry},
				{key: ingressKey(identityFoo, 17, 8080, 16), found: true, entry: DenyEntry},
				{key: ingressKey(identityFoo, 6, 8080, 16), found: true, entry: DenyEntry},
				{key: ingressKey(identityFoo, 6, 80, 16), found: true, entry: DenyEntry},
			},
		}, {
			name: "ordered test-3a: CIDR deny with an earlier order allow hole",
			// 42: allow 1.1.1.1:u53
			// 43: deny 1.1.0.0/16
			// 43: deny world
			// 99: deny everything
			// 100: deny everything
			entries: types.PolicyEntries{
				&types.PolicyEntry{
					L3:       selectors1111,
					L4:       portUDP53,
					Priority: 42,
					Verdict:  types.Allow,
				},
				&types.PolicyEntry{
					L3:       types.ToSelectors(api.EntitySelectorMapping[api.EntityWorld]...),
					Verdict:  types.Deny,
					Priority: 43,
				},
				&types.PolicyEntry{
					L3:       selectors1100,
					Verdict:  types.Deny,
					Priority: 43,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					Verdict:  types.Deny,
					Priority: 99,
				},
				&types.PolicyEntry{
					L3:       types.Selectors{},
					Verdict:  types.Deny,
					Priority: 100,
				},
			},

			expected: map[Key]mapStateEntry{
				// default allow ingress
				ingressKey(0, 0, 0, 0):              newAllowEntryWithLabels(LabelsAllowAnyIngress),
				egressKey(identity1111, 17, 53, 16): allowEntry.withLevel(0),
				egressL3OnlyKey(identityWorld):      denyEntry.withLevel(1),
				egressL3OnlyKey(identityWorldIPv4):  denyEntry.withLevel(1),
				egressL3OnlyKey(identityWorldIPv6):  denyEntry.withLevel(1),
				egressL3OnlyKey(identity1111):       denyEntry.withLevel(1),
				egressL3OnlyKey(identity1100):       denyEntry.withLevel(1),
			},
			probes: []probe{
				{key: egressKey(identity1111, 6, 53, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1111, 17, 53, 16), found: true, entry: AllowEntry},
				{key: egressKey(identity1111, 132, 53, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 6, 53, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 6, 443, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 17, 53, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 17, 443, 16), found: true, entry: DenyEntry},
				{key: egressKey(identity1100, 17, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identityWorld, 6, 53, 16), found: true, entry: DenyEntry},
				{key: egressKey(identityWorld, 6, 443, 16), found: true, entry: DenyEntry},
				{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
				{key: egressKey(identityWorld, 17, 53, 16), found: true, entry: DenyEntry},
				{key: egressKey(identityWorld, 17, 443, 16), found: true, entry: DenyEntry},
				{key: egressKey(identityWorld, 17, 80, 16), found: true, entry: DenyEntry},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			repo := newPolicyDistillery(t, selectorCache)
			for _, entry := range tt.entries {
				entry.Subject = wildcardSubject
				if !tt.skipDefaultDeny {
					entry.DefaultDeny = true
				}
			}
			repo.MustAddPolicyEntries(tt.entries)
			expected := testMapState(t, tt.expected)
			logBuffer := new(bytes.Buffer)
			repo = repo.WithLogBuffer(logBuffer)
			repo.policyCache.insert(identity)
			epp, err := repo.distillEndpointPolicy(logger, DummyOwner{}, identity)
			require.NoError(t, err)
			epp.Ready()
			epp.Detach(logger)
			mapstate := epp.policyMapState

			if equal := assert.True(t, mapstate.Equal(&expected), mapstate.diff(&expected)); !equal {
				t.Logf("Expected Mapstate:\n%s\n", expected)
				t.Logf("Obtained Mapstate:\n%s\n", mapstate)
				t.Logf("Policy Trace: \n%s\n", logBuffer.String())
				t.Errorf("Policy test, %q, obtained didn't match expected for endpoint %s", tt.name, labelsFoo)
			}

			// run probes
			ms := mapstate
			for _, probe := range tt.probes {
				v, found := ms.lookup(probe.key)
				require.Equal(t, probe.found, found, "%s: Entry find mismatch for key %s", tt.name, probe.key)
				// ignore level for probe results
				probe.entry.Precedence = v.Precedence
				require.Equalf(t, probe.entry, v.MapStateEntry, "%s: Verdict mismatch for key %s:\n- %s\n+ %s\n\nMapState:\n%s", tt.name, probe.key, probe.entry, v.MapStateEntry, ms)
			}
		})
	}
}
