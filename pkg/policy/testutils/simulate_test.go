// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	selA  = types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("id=a"))
	selWC = types.WildcardSelector

	idA = identity.NewIdentityFromLabelArray(1001, labels.ParseSelectLabelArray("k8s:id=a", "k8s:foo=bar"))
	idB = identity.NewIdentityFromLabelArray(1002, labels.ParseSelectLabelArray("k8s:id=b", "k8s:foo=bar"))

	// All flows have this as a source
	idSrc  = identity.NewIdentityFromLabelArray(999, labels.ParseSelectLabelArray("k8s:id=src"))
	selSrc = types.NewLabelSelectorFromLabels(labels.ParseSelectLabel("id=src"))
)

func mkEntry(peer types.Selector, startPort, endPort uint16, tier types.Tier, prio float64, verdict types.Verdict) *types.PolicyEntry {
	entry := types.PolicyEntry{
		Tier:        tier,
		Priority:    prio,
		Subject:     selSrc,
		L3:          types.Selectors{peer},
		Verdict:     verdict,
		DefaultDeny: true,
	}

	if startPort > 0 {
		entry.L4 = api.PortRules{{
			Ports: []api.PortProtocol{{
				Protocol: api.ProtoTCP,
				Port:     fmt.Sprintf("%d", startPort),
				EndPort:  int32(endPort),
			}},
		}}
	}

	return &entry
}

type probe struct {
	dst   *identity.Identity
	port  uint16
	allow bool
}

func TestIteratePolicy(t *testing.T) {

	for i, tc := range []struct {
		entries types.PolicyEntries
		probes  []probe
	}{
		// allow all egress
		{
			types.PolicyEntries{mkEntry(selWC, 0, 0, 0, 0, types.Allow)},
			[]probe{
				{idA, 80, true},
				{idB, 90, true},
			},
		},
		// 0.0: deny 80
		// 0.1: allow A
		{
			types.PolicyEntries{
				mkEntry(selWC, 80, 0, 0, 0, types.Deny),
				mkEntry(selA, 0, 0, 0, 1, types.Allow),
			},
			[]probe{
				{idA, 80, false},
				{idA, 81, true},
				{idB, 80, false},
				{idB, 81, false},
			},
		},
		// 0.0: allow A
		// 0.1: deny 80
		{
			types.PolicyEntries{
				mkEntry(selA, 0, 0, 0, 0, types.Allow),
				mkEntry(selWC, 80, 0, 0, 1, types.Deny),
			},
			[]probe{
				{idA, 80, true},
				{idA, 81, true},
				{idB, 80, false},
				{idB, 81, false},
			},
		},
		// 0.0: pass A
		// 0.1: deny 80
		// 1.0: allow A 80
		{
			types.PolicyEntries{
				mkEntry(selA, 0, 0, 0, 0, types.Pass),
				mkEntry(selWC, 80, 0, 0, 1, types.Deny),
				mkEntry(selA, 80, 0, 1, 0, types.Allow),
			},
			[]probe{
				{idA, 80, true},
				{idA, 81, false},
				{idB, 80, false},
				{idB, 81, false},
			},
		},
	} {
		for j, probe := range tc.probes {
			t.Run(fmt.Sprintf("%d/%d", i, j), func(t *testing.T) {
				flow := types.Flow{
					From:  idSrc,
					To:    probe.dst,
					Dport: probe.port,
					Proto: u8proto.TCP,
				}
				verdict, _, _ := IteratePolicy(tc.entries, flow)
				require.Equal(t, probe.allow, verdict.Egress == types.DecisionAllowed, "flow idA -> %s:%d", probe.dst.Labels, probe.port)
			})
		}
	}
}
