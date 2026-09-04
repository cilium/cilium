// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

func PolicyMapCmd(epl endpointmanager.EndpointsLookup) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary:          "Dump an endpoint's realized BPF policymap",
			Args:             "ep-id",
			AutocompleteArgs: autocompleteEndpoints(epl),
			Detail: []string{
				"Dumps the realized BPF policymap for the given endpoint as a",
				"sorted table. This is the realized counterpart to",
				"policy/mapstate/entries, which dumps the desired MapState.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("expected one arg (ep-id) but got %d", len(args))
			}
			eps, err := lookupEPs(epl, args)
			if err != nil {
				return nil, err
			}
			if len(eps) != 1 {
				return nil, fmt.Errorf("expected one endpoint but got %d", len(eps))
			}
			ep := eps[0]
			return func(*script.State) (stdout, stderr string, err error) {
				entries, err := ep.DumpPolicyMap()
				if err != nil {
					return "", "", fmt.Errorf("dump policymap: %w", err)
				}
				return formatPolicyMap(entries), "", nil
			}, nil
		},
	)
}

func formatPolicyMap(entries policymap.PolicyEntriesDump) string {
	// GetDestPort of a port range is the masked start port, so the prefix
	// length is what separates an aggregate entry from an exact entry rooted
	// at the same port.
	slices.SortFunc(entries, func(a, b policymap.PolicyEntryDump) int {
		return cmp.Or(
			cmp.Compare(a.Key.TrafficDirection, b.Key.TrafficDirection),
			cmp.Compare(a.Key.Identity, b.Key.Identity),
			cmp.Compare(a.Key.Nexthdr, b.Key.Nexthdr),
			cmp.Compare(a.Key.GetDestPort(), b.Key.GetDestPort()),
			cmp.Compare(a.Key.Prefixlen, b.Key.Prefixlen),
		)
	})

	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 5, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Direction\tIdentity\tPortProto\tAction\tProxyPort")
	for _, e := range entries {
		dir := trafficdirection.TrafficDirection(e.Key.TrafficDirection).String()
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%d\n",
			dir, e.Key.Identity, e.Key.PortProtoString(),
			e.PolicyEntry.Flags, e.PolicyEntry.GetProxyPort())
	}
	w.Flush()
	return sb.String()
}
