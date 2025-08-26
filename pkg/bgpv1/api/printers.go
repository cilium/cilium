// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	bgppacket "github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/cilium/cilium/api/v1/models"
)

// PrintBGPPeersTable prints table of provided BGP peers in the provided tab writer.
func PrintBGPPeersTable(w *tabwriter.Writer, peers []*models.BgpPeer, printUptime bool) {
	// sort by local AS, if peers from same AS then sort by peer address.
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].LocalAsn != peers[j].LocalAsn {
			return peers[i].LocalAsn < peers[j].LocalAsn
		}
		return peers[i].PeerAddress < peers[j].PeerAddress
	})

	if printUptime {
		fmt.Fprintln(w, "Local AS\tPeer AS\tPeer Address\tSession\tUptime\tFamily\tReceived\tAdvertised")
	} else {
		fmt.Fprintln(w, "Local AS\tPeer AS\tPeer Address\tSession\tFamily\tReceived\tAdvertised")
	}
	for _, peer := range peers {
		fmt.Fprintf(w, "%d\t", peer.LocalAsn)
		fmt.Fprintf(w, "%d\t", peer.PeerAsn)
		fmt.Fprintf(w, "%s:%d\t", peer.PeerAddress, peer.PeerPort)
		fmt.Fprintf(w, "%s\t", peer.SessionState)

		if printUptime {
			// Time is rounded to nearest second
			fmt.Fprintf(w, "%s\t", time.Duration(peer.UptimeNanoseconds).Round(time.Second).String())
		}

		for i, afisafi := range peer.Families {
			if i > 0 {
				// move to align with afi-safi
				tabs := 4
				if printUptime {
					tabs++
				}
				fmt.Fprint(w, strings.Repeat("\t", tabs))
			}
			// AFI and SAFI are concatenated for brevity
			fmt.Fprintf(w, "%s/%s\t", afisafi.Afi, afisafi.Safi)
			fmt.Fprintf(w, "%d\t", afisafi.Received)
			fmt.Fprintf(w, "%d\n", afisafi.Advertised)
		}
	}
	w.Flush()
}

// PrintBGPRoutesTable prints table of provided BGP routes in the provided tab writer.
func PrintBGPRoutesTable(w *tabwriter.Writer, routes []*models.BgpRoute, printPeer, printAge bool) error {
	// sort first by ASN, then by neighbor, then by prefix
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].RouterAsn != routes[j].RouterAsn {
			return routes[i].RouterAsn < routes[j].RouterAsn
		}
		if routes[i].Neighbor != routes[j].Neighbor {
			return routes[i].Neighbor < routes[j].Neighbor
		}
		return routes[i].Prefix < routes[j].Prefix
	})

	fmt.Fprintf(w, "VRouter\t")
	if printPeer {
		fmt.Fprintf(w, "Peer\t")
	}
	fmt.Fprintf(w, "Prefix\tNextHop\t")
	if printAge {
		fmt.Fprintf(w, "Age\t")
	}
	fmt.Fprintf(w, "Attrs\n")

	for _, route := range routes {
		r, err := ToAgentRoute(route)
		if err != nil {
			return err
		}
		for _, path := range r.Paths {
			fmt.Fprintf(w, "%d\t", route.RouterAsn)
			if printPeer {
				fmt.Fprintf(w, "%s\t", route.Neighbor)
			}
			fmt.Fprintf(w, "%s\t", path.NLRI)
			fmt.Fprintf(w, "%s\t", NextHopFromPathAttributes(path.PathAttributes))
			if printAge {
				fmt.Fprintf(w, "%s\t", time.Duration(path.AgeNanoseconds).Round(time.Second))
			}
			fmt.Fprintf(w, "%s\n", path.PathAttributes)
		}
	}
	w.Flush()
	return nil
}

// PrintBGPRoutePoliciesTable prints table of provided BGP route policies in the provided tab writer.
func PrintBGPRoutePoliciesTable(w *tabwriter.Writer, policies []*models.BgpRoutePolicy) {
	// sort by router ASN, if policies from same ASN then sort by policy name.
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].RouterAsn != policies[j].RouterAsn {
			return policies[i].RouterAsn < policies[j].RouterAsn
		}
		return policies[i].Name < policies[j].Name
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
			fmt.Fprintf(w, "%s\n", formatStringArray(formatPathActions(stmt)))
		}
		if len(policy.Statements) == 0 {
			fmt.Fprintf(w, "\n")
		}
	}
	w.Flush()
}

// NextHopFromPathAttributes returns the next hop address determined by the list of provided BGP path attributes.
func NextHopFromPathAttributes(pathAttributes []bgppacket.PathAttributeInterface) string {
	for _, a := range pathAttributes {
		switch attr := a.(type) {
		case *bgppacket.PathAttributeNextHop:
			return attr.Value.String()
		case *bgppacket.PathAttributeMpReachNLRI:
			return attr.Nexthop.String()
		}
	}
	return "0.0.0.0"
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
