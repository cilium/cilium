// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"cmp"
	"slices"
	"strconv"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

var lblsDefaultAllow = labels.LabelArrayFromString("[reserved:default-allow]")
var lblsDefaultDeny = labels.LabelArrayFromString("[reserved:default-deny]")

// IteratePolicy is a simple step-by-step policy iteration simulator.
// It is used to validate the policy implementation.
func IteratePolicy(entries types.PolicyEntries, flow types.Flow) (verdict types.LookupResult, egressLbls, ingressLbls labels.LabelArray) {
	// get set of entries for egress from src and ingress from dst
	egressEntries, egressDefaultDeny := findEntries(entries, flow, false)
	ingressEntries, ingressDefaultDeny := findEntries(entries, flow, true)

	// Evaluate rules
	egressDecision, egressLbls := findMatchingRule(egressEntries, egressDefaultDeny)
	ingressDecision, ingressLbls := findMatchingRule(ingressEntries, ingressDefaultDeny)

	return types.LookupResult{
		Egress:  egressDecision,
		Ingress: ingressDecision,
	}, egressLbls, ingressLbls
}

// This assumes matchingEntries is a sorted list of all entries that match this traffic.
// It runs through the entries until one expresses a verdict.
func findMatchingRule(matchingEntries types.PolicyEntries, defaultDeny bool) (verdict types.Decision, lbls labels.LabelArray) {
	if len(matchingEntries) == 0 {
		if defaultDeny {
			return types.DecisionDenied, lblsDefaultDeny
		} else {
			return types.DecisionAllowed, lblsDefaultAllow
		}
	}

	// Ignore all tiers below this value
	var skipTierBefore types.Tier = 0

	// loop through entries, skipping tiers as directed via PASS
	for _, entry := range matchingEntries {
		if skipTierBefore > entry.Tier {
			continue
		}
		switch entry.Verdict {
		case types.Pass:
			skipTierBefore = entry.Tier + 1
			continue
		case types.Deny:
			return types.DecisionDenied, entry.Labels
		case types.Allow:
			return types.DecisionAllowed, entry.Labels
		}
	}
	return types.DecisionDenied, lblsDefaultDeny
}

// findEntries finds all traffic that matches a given subject + flow
// returns true if default-deny should be enabled.
func findEntries(entries types.PolicyEntries, flow types.Flow, ingress bool) (types.PolicyEntries, bool) {
	subject := flow.From
	peer := flow.To
	if ingress {
		subject = flow.To
		peer = flow.From
	}

	out := types.PolicyEntries{}
	defaultDeny := false
	for _, entry := range entries {
		if entry.Ingress != ingress {
			continue
		}
		if !entry.Subject.Matches(subject.LabelArray) {
			continue
		}

		// The subject, matches, determine default deny state
		defaultDeny = defaultDeny || entry.DefaultDeny

		// nil L3 = match nothing. Empty L3 = match everything. Bah.
		if entry.L3 == nil {
			continue
		}

		// Check if peer matches
		if !entry.L3.SelectsAllEndpoints() && !entry.L3.Matches(peer.LabelArray) {
			continue
		}

		if len(entry.L4) == 0 {
			out = append(out, entry)
		} else {
			// Flatten multiple L4 entries to multiple top-level policy entries
			for _, pr := range flattenMatchingL4(flow, entry) {
				newEntry := *entry
				newEntry.L4 = api.PortRules{pr}
				out = append(out, &newEntry)
			}
		}
	}
	sort(out)
	return out, defaultDeny
}

// flattenMatchingL4 returns an array matching port rules. Each portrule will have exactly one entry in Ports
func flattenMatchingL4(flow types.Flow, entry *types.PolicyEntry) api.PortRules {
	out := api.PortRules{}
	for _, pr := range entry.L4 {
		for _, portProto := range pr.Ports {
			// check l4 protocol for match (ANY or specific)
			if portProto.Protocol != api.ProtoAny && portProto.Protocol != api.L4Proto(flow.Proto.String()) {
				continue
			}

			// evaluate named ports
			var startPort uint16
			var namedPorts map[string]uint16
			switch portProto.Protocol {
			case api.ProtoTCP:
				namedPorts = flow.NamedPortsTCP
			case api.ProtoUDP:
				namedPorts = flow.NamedPortsUDP
			}
			startPort = namedPorts[portProto.Port]

			if startPort == 0 {
				sp, err := strconv.Atoi(portProto.Port)
				if err != nil {
					// This is just test code, panicking is OK
					panic("named port not found")
				}
				startPort = uint16(sp)
			}

			// match either exact start port or range
			if (startPort == 0 && portProto.EndPort == 0) || // wildcard port
				startPort == flow.Dport || // exact match
				(portProto.EndPort != 0 && (startPort <= flow.Dport && flow.Dport <= uint16(portProto.EndPort))) { // range match

				out = append(out, api.PortRule{
					Ports: []api.PortProtocol{portProto},
					Rules: pr.Rules,
				})
			}
		}
	}
	return out
}

// Sort rules by precedence:
// - lowest tier first
// - lowest priority within tier
// - same tier + priority: deny, proxy, allow
func sort(entries types.PolicyEntries) {
	slices.SortFunc(entries, func(a, b *types.PolicyEntry) int {
		// Tier
		if sign := cmp.Compare(a.Tier, b.Tier); sign != 0 {
			return sign
		}

		// Prio
		if sign := cmp.Compare(a.Priority, b.Priority); sign != 0 {
			return sign
		}

		// deny before allow before pass
		verdictOrder := map[types.Verdict]int{
			types.Deny:  0,
			types.Allow: 1,
			types.Pass:  2,
		}

		return cmp.Compare(verdictOrder[a.Verdict], verdictOrder[b.Verdict])
	})
}
