// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/client/bgp"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

var BgpRoutePoliciesCmd = &cobra.Command{
	Use:     "route-policies [vrouter <asn>]",
	Aliases: []string{"rps"},
	Short:   "List configured route policies",
	Long:    "List route policies configured in the underlying routing daemon",
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		params := bgp.NewGetBgpRoutePoliciesParams()

		// parse [vrouter <asn>]
		if len(args) > 0 {
			var asn int64
			asn, _, err = parseVRouterASN(args)
			if err != nil {
				Fatalf("failed to parse vrouter ASN: %s\n", err)
			}
			params.RouterAsn = ptr.To[int64](asn)
		}

		res, err := client.Bgp.GetBgpRoutePolicies(params)
		if err != nil {
			disabledErr := bgp.NewGetBgpRoutePoliciesDisabled()
			if errors.As(err, &disabledErr) {
				fmt.Println("BGP Control Plane is disabled")
				return
			}
			Fatalf("cannot get route policies list: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(res.GetPayload()); err != nil {
				Fatalf("error getting output in JSON: %s\n", err)
			}
		} else {
			printBGPRoutePoliciesTable(res.GetPayload())
		}
	},
}

func printBGPRoutePoliciesTable(policies []*models.BgpRoutePolicy) {
	// get new tab writer with predefined defaults
	w := NewTabWriter()

	// sort by router ASN, if policies from same ASN then sort by policy name.
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].RouterAsn < policies[j].RouterAsn && policies[i].Name < policies[j].Name
	})

	fmt.Fprintln(w, "VRouter\tPolicy Name\tType\tMatch Peers\tMatch Families\tMatch Prefixes (Min..Max Len)\tRIB Action\tPath Actions")
	for _, policy := range policies {
		fmt.Fprintf(w, "%d\t", policy.RouterAsn)
		fmt.Fprintf(w, "%s\t", policy.Name)
		fmt.Fprintf(w, "%s\t", policy.Type)

		for i, stmt := range policy.Statements {
			if i > 0 {
				fmt.Fprint(w, strings.Repeat("\t", 3))
			}
			fmt.Fprintf(w, "%s\t", formatStringArray(stmt.MatchNeighbors))
			fmt.Fprintf(w, "%s\t", formatStringArray(formatFamilies(stmt.MatchFamilies)))
			fmt.Fprintf(w, "%s\t", formatStringArray(formatMatchPrefixes(stmt.MatchPrefixes)))
			fmt.Fprintf(w, "%s\t", stmt.RouteAction)
			fmt.Fprintf(w, "%s\t", formatStringArray(formatPathActions(stmt)))
			fmt.Fprintf(w, "\n")
		}
		if len(policy.Statements) == 0 {
			fmt.Fprintf(w, "\n")
		}
	}
	w.Flush()
}

func formatStringArray(arr []string) string {
	if len(arr) == 1 {
		return arr[0]
	}
	res := ""
	for _, str := range arr {
		res += "{" + str + "} "
	}
	return strings.TrimSpace(res)
}

func formatFamilies(families []*models.BgpFamily) []string {
	var res []string
	for _, f := range families {
		res = append(res, fmt.Sprintf("%s/%s", f.Afi, f.Safi))
	}
	return res
}

func formatMatchPrefixes(pfxs []*models.BgpRoutePolicyPrefixMatch) []string {
	var res []string
	for _, p := range pfxs {
		res = append(res, fmt.Sprintf("%s (%d..%d)", p.Cidr, p.PrefixLenMin, p.PrefixLenMax))
	}
	return res
}

func formatPathActions(stmt *models.BgpRoutePolicyStatement) []string {
	var res []string
	if stmt.SetLocalPreference >= 0 {
		res = append(res, fmt.Sprintf("SetLocalPreference: %d", stmt.SetLocalPreference))
	}
	if len(stmt.AddCommunities) > 0 {
		res = append(res, fmt.Sprintf("AddCommunities: %v", stmt.AddCommunities))
	}
	if len(stmt.AddLargeCommunities) > 0 {
		res = append(res, fmt.Sprintf("AddLargeCommunities: %v", stmt.AddLargeCommunities))
	}
	return res
}

func init() {
	BgpCmd.AddCommand(BgpRoutePoliciesCmd)
	command.AddOutputOption(BgpRoutePoliciesCmd)
}
