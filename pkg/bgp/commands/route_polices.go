// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/types"
)

func BGPRoutePoliciesCmd(bgpMgr agent.BGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP route policies on Cilium",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(instanceFlag, instanceFlagShort, "", "Name of a Cilium router instance. Lists policies of all instances if omitted.")
				addOutFileFlag(fs)
			},
			Detail: []string{
				"Lists route policies configured in Cilium BGP Control Plane.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			instance, err := s.Flags.GetString(instanceFlag)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				res, err := bgpMgr.GetRoutePolicies(s.Context(), &agent.GetRoutePoliciesRequest{
					InstanceName: instance,
				})
				if err != nil {
					return "", "", err
				}

				w, buf, f, err := getCmdWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}
				tw := getCmdTabWriter(w)

				PrintBGPRoutePoliciesTable(tw, res.Instances)
				tw.Flush()

				return buf.String(), "", err
			}, nil
		},
	)
}

// PrintBGPRoutePoliciesTable prints table of provided BGP route policies in the provided tab writer.
func PrintBGPRoutePoliciesTable(tw *tabwriter.Writer, instances []agent.InstanceRoutePolicies) {
	type row struct {
		Instance      string
		PolicyName    string
		Type          string
		MatchPeers    string
		MatchFamilies string
		MatchPrefixes string
		RIBAction     string
		PathActions   string
	}

	var rows []row

	for _, instance := range instances {
		for _, policy := range instance.RoutePolicies {
			for _, stmt := range policy.Statements {
				rows = append(rows, row{
					Instance:      instance.Name,
					PolicyName:    policy.Name,
					Type:          policy.Type.String(),
					MatchPeers:    formatMatchNeighbors(stmt.Conditions.MatchNeighbors),
					MatchFamilies: formatFamilies(stmt.Conditions.MatchFamilies),
					MatchPrefixes: formatMatchPrefixes(stmt.Conditions.MatchPrefixes),
					RIBAction:     stmt.Actions.RouteAction.String(),
					PathActions:   formatPathActions(stmt),
				})
			}
		}
	}

	// Sort by Instance, PolicyName
	slices.SortFunc(rows, func(a, b row) int {
		c := strings.Compare(a.Instance, b.Instance)
		if c != 0 {
			return c
		}
		return strings.Compare(a.PolicyName, b.PolicyName)
	})

	rows = slices.Insert(rows, 0, row{
		Instance:      "Instance",
		PolicyName:    "Policy Name",
		Type:          "Type",
		MatchPeers:    "Match Peers",
		MatchFamilies: "Match Families",
		MatchPrefixes: "Match Prefixes (Min..Max Len)",
		RIBAction:     "RIB Action",
		PathActions:   "Path Actions",
	})

	for _, row := range rows {
		fmt.Fprintf(tw, "%s\n", strings.Join([]string{
			row.Instance,
			row.PolicyName,
			row.Type,
			row.MatchPeers,
			row.MatchFamilies,
			row.MatchPrefixes,
			row.RIBAction,
			row.PathActions,
		}, "\t"))
	}

}

func formatMatchNeighbors(match *types.RoutePolicyNeighborMatch) string {
	if match == nil || len(match.Neighbors) == 0 {
		return ""
	}
	neighborsStr := formatIPAddrArray(match.Neighbors)
	if len(match.Neighbors) > 1 {
		return fmt.Sprintf("(%s) %s", match.Type, neighborsStr)
	}
	return neighborsStr
}

func formatFamilies(families []types.Family) string {
	var res []string
	for _, f := range families {
		res = append(res, fmt.Sprintf("%s/%s", f.Afi, f.Safi))
	}
	return formatStringArray(res)
}

func formatMatchPrefixes(match *types.RoutePolicyPrefixMatch) string {
	if match == nil || len(match.Prefixes) == 0 {
		return ""
	}
	var prefixes []string
	for _, p := range match.Prefixes {
		prefixes = append(prefixes, fmt.Sprintf("%s (%d..%d)", p.CIDR, p.PrefixLenMin, p.PrefixLenMax))
	}
	prefixesStr := formatStringArray(prefixes)
	if len(prefixes) > 1 || match.Type == types.RoutePolicyMatchInvert {
		return fmt.Sprintf("(%s) %s", match.Type, prefixesStr)
	}
	return prefixesStr
}

func formatPathActions(stmt *types.RoutePolicyStatement) string {
	var res []string
	if stmt.Actions.SetLocalPreference != nil && *stmt.Actions.SetLocalPreference >= 0 {
		res = append(res, fmt.Sprintf("SetLocalPreference: %d", *stmt.Actions.SetLocalPreference))
	}
	if len(stmt.Actions.AddCommunities) > 0 {
		res = append(res, fmt.Sprintf("AddCommunities: %v", stmt.Actions.AddCommunities))
	}
	if len(stmt.Actions.AddLargeCommunities) > 0 {
		res = append(res, fmt.Sprintf("AddLargeCommunities: %v", stmt.Actions.AddLargeCommunities))
	}
	return formatStringArray(res)
}

func formatIPAddrArray(arr []netip.Addr) string {
	if len(arr) == 1 {
		return arr[0].String()
	}
	res := strings.Builder{}
	for _, ip := range arr {
		res.WriteString("{" + ip.String() + "} ")
	}
	return strings.TrimSpace(res.String())
}

func formatStringArray(arr []string) string {
	if len(arr) == 1 {
		return arr[0]
	}
	res := strings.Builder{}
	for _, str := range arr {
		res.WriteString("{" + str + "} ")
	}
	return strings.TrimSpace(res.String())
}
