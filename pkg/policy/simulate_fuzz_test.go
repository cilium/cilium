// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/testutils"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Fuzzes policy by generating random sets of rules, then generating the mapstate
// and testing a number of flows against both mapstate and the simulation engine.
//
// If the verdicts diverge, reports an error.
func FuzzDistillPolicy(f *testing.F) {
	debug := true

	f.Fuzz(func(t *testing.T, inp []byte) {
		logger := hivetest.Logger(t)
		td := newTestData(t, logger).withIDs(ruleTestIDs)
		flows := makeFlows([]*identity.Identity{idB, idC})

		if len(inp) < 2 {
			return
		}

		entries := makeFuzzEntries(inp)
		td.repo.ReplaceByResource(entries, "asdf")

		if debug {
			strs := []string{}
			defaultDeny := false
			for _, entry := range entries {
				if entry.DefaultDeny {
					defaultDeny = true
				}
				strs = append(strs, entry.Log.Value)
			}
			t.Log("Rule corpus:\n" + strings.Join(strs, "\n") + fmt.Sprintf("\n- default deny: %v\n", defaultDeny))
		}

		// resolve policy
		srcEP := &endpointInfo{
			ID: uint64(idA.ID),
		}

		selPol, _, err := td.repo.GetSelectorPolicy(idA, 0, &dummyPolicyStats{}, 1)
		if err != nil {
			t.Fatal(err) // should never happen
		}

		epp := selPol.DistillPolicy(logger, srcEP, nil)
		epp.Ready()
		epp.Detach(logger)

		if debug {
			t.Log("Policy map:\n" + epp.policyMapState.String())
		}

		for _, flow := range flows {
			// lookup from the distilled map state
			key := EgressKey().WithIdentity(flow.To.ID).WithPortProto(flow.Proto, flow.Dport)
			if debug {
				t.Log("Lookup key", key.String())
			}

			egressEntry, meta, found := epp.Lookup(key)

			if debug {
				t.Log("Lookup result",
					"entry", egressEntry.String(),
					"meta", meta,
					"found", found)
			}

			// simulate policy iteratively
			simulateVerdict, _, _ := testutils.IteratePolicy(entries, flow)

			require.Equal(t, simulateVerdict.Egress == types.DecisionAllowed, egressEntry.IsAllow(), "Flow verdict mismatch %s -> %s (%d) port %d", flow.From.Labels["name"].Value, flow.To.Labels["name"].Value, flow.To.ID, flow.Dport)
		}
	})
}

var (
	fuzzCorpusL3s = []types.Selectors{
		{types.WildcardSelector},
		{types.ToSelector(endpointSelectorB)},
		{types.ToSelector(endpointSelectorC)},
		// selects b and c, but different selector
		{types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("k8s:io.kubernetes.pod.namespace=default"))},
	}

	fuzzCorpusL3Descs = []string{
		"*",
		"idB",
		"idC",
		"idB+C",
	}

	fuzzCorpusL3WithAggregates = []types.Selectors{
		{types.WildcardSelector},
		{types.ToSelector(endpointSelectorB)},

		types.ToSelectors(api.EntitySlice{"world"}.GetAsEndpointSelectors()...),
		{types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("cidr:1.1.1.1/30"))},

		types.ToSelectors(api.EntitySlice{"remote-node"}.GetAsEndpointSelectors()...),
		{types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("k8s:nodename=nodeC"))},
	}

	fuzzCorpusL3WithAggregatesDescs = []string{
		"*",
		"idB",
		"world",
		"cidr:1.1.1.1/30",
		"remote-node",
		"nodeC",
	}

	identity1111 = identity.NewIdentity(localIdentity(1111),
		labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("1.1.1.1/32")))))

	identityNodeC = identity.NewIdentity(identity.IdentityScopeRemoteNode+1,
		labels.FromSlice([]labels.Label{
			labels.NewLabel("nodename", "nodeC", labels.LabelSourceK8s),
			labels.NewLabel("remote-node", "", labels.LabelSourceReserved),
		}))

	fuzzCorpusAggregateIDs = identity.IdentityMap{
		idA.ID:           idA.LabelArray,
		idB.ID:           idB.LabelArray,
		identity1111.ID:  identity1111.LabelArray,
		identityNodeC.ID: identityNodeC.LabelArray,
	}

	// All possible port ranges between 4-7
	fuzzCorpusL4s = []api.PortRules{
		nil,
		mkport(4, 7),
		mkport(4, 5),
		mkport(6, 7),
		mkport(4, 0),
		mkport(5, 0),
		mkport(6, 0),
		mkport(7, 0),
	}

	fuzzCorpusL4Descs = []string{
		"*",
		"4-7",
		"4-5",
		"6-7",
		"4",
		"5",
		"6",
		"7",
	}
)

func makeFuzzEntries(input []byte) types.PolicyEntries {
	out := make(types.PolicyEntries, 0, len(input)/2)
	// For every byte, select a l3, l4 and verdict.
	for i := range len(input) / 2 {
		b := input[i*2]

		prio := input[i*2+1]

		// Take bottom two bits of prio for tier
		tier := types.TierUnspec
		switch prio & 0b0000_0011 {
		case 0:
			tier = types.Admin
		case 1, 3:
			tier = types.Normal
		case 2:
			tier = types.Baseline
		}
		prio = prio >> 2

		// bit 0-1: l3
		l3 := b & 0b0000_0011

		// bit 2-4: l4
		l4 := b & 0b0001_1100
		l4 = l4 >> 2

		// bit 5 & 6: verdict
		verdict := types.Verdict((b & 0b0110_0000) >> 5)
		if verdict >= 3 {
			verdict = types.Pass
		}

		out = append(out, &types.PolicyEntry{
			Tier:        tier,
			Priority:    float64(prio),
			Subject:     labelSelectorA,
			L3:          fuzzCorpusL3s[l3],
			L4:          fuzzCorpusL4s[l4],
			Verdict:     verdict,
			Ingress:     false,
			DefaultDeny: true,
			Log:         api.LogConfig{Value: fmt.Sprintf("%d.%d %s:%s %s", tier, prio, fuzzCorpusL3Descs[l3], fuzzCorpusL4Descs[l4], verdict)},
		})
	}
	return out
}

func makeFuzzEntriesAggregated(input []byte) types.PolicyEntries {
	out := make(types.PolicyEntries, 0, len(input)/2)
	// For every byte, select a l3, l4 and verdict.
	for i := range len(input) / 2 {
		b := input[i*2]

		prio := input[i*2+1]

		// Take bottom two bits of prio for tier
		tier := types.TierUnspec
		switch prio & 0b0000_0011 {
		case 0:
			tier = types.Admin
		case 1, 3:
			tier = types.Normal
		case 2:
			tier = types.Baseline
		}
		prio = prio >> 2

		// bit 0, 1, 2: l3
		l3 := (b & 0b0000_0111) % 6

		// bit 3, 4, 5: l4
		l4 := b & 0b0011_1000
		l4 = l4 >> 3

		// bit 6 & 7: verdict
		verdict := types.Verdict((b & 0b1100_0000) >> 6)
		if verdict >= 3 {
			verdict = types.Pass
		}

		out = append(out, &types.PolicyEntry{
			Tier:        tier,
			Priority:    float64(prio),
			Subject:     labelSelectorA,
			L3:          fuzzCorpusL3WithAggregates[l3],
			L4:          fuzzCorpusL4s[l4],
			Verdict:     verdict,
			Ingress:     false,
			DefaultDeny: true,
			Log:         api.LogConfig{Value: fmt.Sprintf("%d.%d %s:%s %s", tier, prio, fuzzCorpusL3WithAggregatesDescs[l3], fuzzCorpusL4Descs[l4], verdict)},
		})
	}
	return out
}

func makeFlows(ids []*identity.Identity) []types.Flow {
	out := []types.Flow{}
	for _, dest := range ids {
		for _, dport := range []uint16{4, 5, 6, 7} {
			out = append(out, types.Flow{
				From:  idA,
				To:    dest,
				Proto: u8proto.TCP,
				Dport: dport,
			})

		}
	}
	return out
}

func mkport(start, end int) api.PortRules {
	return api.PortRules{{
		Ports: []api.PortProtocol{{
			Protocol: api.ProtoTCP,
			Port:     fmt.Sprintf("%d", start),
			EndPort:  int32(end),
		}},
	}}
}

// FuzzDistillPolicyWithAggregates is the same logic as FuzzDistillPolicy, but with
// additional aggregates defined.
func FuzzDistillPolicyWithAggregates(f *testing.F) {
	debug := true

	f.Fuzz(func(t *testing.T, inp []byte) {
		logger := hivetest.Logger(t)
		td := newTestData(t, logger).withIDs(fuzzCorpusAggregateIDs, identity.ListReservedIdentities())
		flows := makeFlows([]*identity.Identity{
			idB,
			identity1111,
			identity.LookupReservedIdentity(identity.ReservedIdentityWorld),
			identity.LookupReservedIdentity(identity.ReservedIdentityWorldIPv4),
			identity.LookupReservedIdentity(identity.ReservedIdentityRemoteNode),
			identity.LookupReservedIdentity(identity.ReservedIdentityKubeAPIServer),
			identityNodeC,
		})

		if len(inp) < 2 {
			return
		}

		entries := makeFuzzEntriesAggregated(inp)
		td.repo.ReplaceByResource(entries, "asdf")

		if debug {
			strs := []string{}
			defaultDeny := false
			for _, entry := range entries {
				if entry.DefaultDeny {
					defaultDeny = true
				}
				strs = append(strs, entry.Log.Value)
			}
			t.Log("Rule corpus:\n" + strings.Join(strs, "\n") + fmt.Sprintf("\n- default deny: %v\n", defaultDeny))
		}

		// resolve policy
		srcEP := &endpointInfo{
			ID: uint64(idA.ID),
		}

		selPol, _, err := td.repo.GetSelectorPolicy(idA, 0, &dummyPolicyStats{}, 1)
		if err != nil {
			t.Fatal(err) // should never happen
		}

		epp := selPol.DistillPolicy(logger, srcEP, nil)
		epp.Ready()
		epp.Detach(logger)

		if debug {
			t.Log("Policy map:\n" + epp.policyMapState.String())
		}

		for _, flow := range flows {
			// lookup from the distilled map state
			key := EgressKey().WithIdentity(flow.To.ID).WithPortProto(flow.Proto, flow.Dport)
			if debug {
				t.Log("Lookup key", key.String())
			}

			egressEntry, meta, found := epp.Lookup(key)

			if debug {
				t.Log("Lookup result",
					"entry", egressEntry.String(),
					"meta", meta,
					"found", found)
			}

			// simulate policy iteratively
			simulateVerdict, _, _ := testutils.IteratePolicy(entries, flow)

			require.Equal(t, simulateVerdict.Egress == types.DecisionAllowed, egressEntry.IsAllow(), "Flow verdict mismatch %s -> %s (%d) port %d", flow.From.Labels["name"].Value, flow.To.Labels["name"].Value, flow.To.ID, flow.Dport)
		}
	})
}
