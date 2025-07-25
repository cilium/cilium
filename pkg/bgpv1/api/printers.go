// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/base64"
	"fmt"
	"io"
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

// PrintBGPPeersCaps prints the capabilities of the provided BGP peers.
func PrintBGPPeersCaps(w io.Writer, peers []*models.BgpPeer) {
	if len(peers) == 0 {
		fmt.Fprintf(w, "No BGP peer sessions found on this node\n")
	}

	for _, peer := range peers {
		fmt.Fprintf(w, "BGP neighbor is %s, remote AS %d\n", peer.PeerAddress, peer.PeerAsn)
		fmt.Fprintf(w, "  Neighbor capabilities:\n")
		if len(peer.RemoteCapabilities) == 0 {
			fmt.Fprintf(w, "    No capabilities found\n")
		}
		for _, cap := range peer.RemoteCapabilities {
			fmt.Fprintf(w, "    %s\n", printCapability(cap))
		}
	}
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
func printCapability(c *models.BgpCapability) string {
	bin, err := base64.StdEncoding.DecodeString(c.Capability)
	if err != nil {
		return fmt.Sprintf("Could not decode from base64 to bytes %s: %s", c.Capability, err)
	}
	capability, err := bgppacket.DecodeCapability(bin)
	if err != nil {
		return fmt.Sprintf("Could not decode from bytes to capability %s: %s", c.Capability, err)
	}
	switch capability.Code() {
	case bgppacket.BGP_CAP_MULTIPROTOCOL:
		m := capability.(*bgppacket.CapMultiProtocol)
		return fmt.Sprintf("%s: %s", m.Code(), m.CapValue)
	case bgppacket.BGP_CAP_GRACEFUL_RESTART:
		grStr := func(g *bgppacket.CapGracefulRestart) string {
			str := "        "
			if len(g.Tuples) > 0 {
				str += fmt.Sprintf("restart time %d sec", g.Time)
			}
			if g.Flags&0x08 > 0 {
				if len(strings.TrimSpace(str)) > 0 {
					str += ", "
				}
				str += "restart flag set"
			}
			if g.Flags&0x04 > 0 {
				if len(strings.TrimSpace(str)) > 0 {
					str += ", "
				}
				str += "notification flag set"
			}

			if len(str) > 0 {
				str += "\n"
			}
			for _, t := range g.Tuples {
				str += fmt.Sprintf("        %s", bgppacket.AfiSafiToRouteFamily(t.AFI, t.SAFI))
				if t.Flags == 0x80 {
					str += ", forward flag set"
				}
				str += "\n"
			}
			return str
		}
		g := capability.(*bgppacket.CapGracefulRestart)
		return fmt.Sprintf("%s:\n%s", g.Code(), grStr(g))
	case bgppacket.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART:
		grStr := func(g *bgppacket.CapLongLivedGracefulRestart) string {
			var str string
			for _, t := range g.Tuples {
				str += fmt.Sprintf("        %s, restart time %d sec", bgppacket.AfiSafiToRouteFamily(t.AFI, t.SAFI), t.RestartTime)
				if t.Flags == 0x80 {
					str += ", forward flag set"
				}
				str += "\n"
			}
			return str
		}
		g := capability.(*bgppacket.CapLongLivedGracefulRestart)
		return fmt.Sprintf("%s:\n%s", g.Code(), grStr(g))
	case bgppacket.BGP_CAP_EXTENDED_NEXTHOP:
		exnhStr := func(e *bgppacket.CapExtendedNexthop) string {
			lines := make([]string, 0, len(e.Tuples))
			for _, t := range e.Tuples {
				var nhafi string
				switch int(t.NexthopAFI) {
				case bgppacket.AFI_IP:
					nhafi = "ipv4"
				case bgppacket.AFI_IP6:
					nhafi = "ipv6"
				default:
					nhafi = fmt.Sprintf("%d", t.NexthopAFI)
				}
				line := fmt.Sprintf("        nlri: %s, nexthop: %s", bgppacket.AfiSafiToRouteFamily(t.NLRIAFI, uint8(t.NLRISAFI)), nhafi)
				lines = append(lines, line)
			}
			return strings.Join(lines, "\n")
		}
		e := capability.(*bgppacket.CapExtendedNexthop)
		return fmt.Sprintf("%s:\n%s", e.Code(), exnhStr(e))
	case bgppacket.BGP_CAP_ADD_PATH:
		addPathStr := func(a *bgppacket.CapAddPath) string {
			var str string
			for _, item := range a.Tuples {
				str += fmt.Sprintf("         %s:\t%s\n", item.RouteFamily, item.Mode)
			}
			return str
		}
		a := capability.(*bgppacket.CapAddPath)
		return fmt.Sprintf("%s:\n%s", a.Code(), addPathStr(a))
	case bgppacket.BGP_CAP_FQDN:
		f := capability.(*bgppacket.CapFQDN)
		return fmt.Sprintf("%s: name: %s, domain: %s", f.Code(), f.HostName, f.DomainName)
	case bgppacket.BGP_CAP_SOFT_VERSION:
		s := capability.(*bgppacket.CapSoftwareVersion)
		return fmt.Sprintf("%s: %s", s.Code(), s.SoftwareVersion)
	default:
		return capability.Code().String()
	}
}
