// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
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
		return
	}

	for _, peer := range peers {
		localCaps, err := decodeBgpCapabilities(peer.LocalCapabilities)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode all local capabilities: %s\n", err)
		}
		remoteCaps, err := decodeBgpCapabilities(peer.RemoteCapabilities)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode all remote capabilities: %s\n", err)
		}

		fmt.Fprintf(w, "BGP neighbor is %s, remote AS %d\n", peer.PeerAddress, peer.PeerAsn)
		fmt.Fprintf(w, "Neighbor capabilities:\n")
		if len(remoteCaps) == 0 && len(localCaps) == 0 {
			fmt.Fprintf(w, "No capabilities found\n")
		} else {
			printLocalRemoteCaps(w, localCaps, remoteCaps)
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
			fmt.Fprintf(w, "%s\t", formatMatchNeighbors(stmt.MatchNeighbors))
			fmt.Fprintf(w, "%s\t", formatStringArray(formatFamilies(stmt.MatchFamilies)))
			fmt.Fprintf(w, "%s\t", formatMatchPrefixes(stmt.MatchPrefixes))
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
	var res strings.Builder
	for _, str := range arr {
		res.WriteString("{" + str + "} ")
	}
	return strings.TrimSpace(res.String())
}

func formatFamilies(families []*models.BgpFamily) []string {
	var res []string
	for _, f := range families {
		res = append(res, fmt.Sprintf("%s/%s", f.Afi, f.Safi))
	}
	return res
}

func formatMatchNeighbors(match *models.BgpRoutePolicyNeighborMatch) string {
	if match == nil || len(match.Neighbors) == 0 {
		return ""
	}
	neighborsStr := formatStringArray(match.Neighbors)
	if len(match.Neighbors) > 1 {
		return fmt.Sprintf("(%s) %s", match.Type, neighborsStr)
	}
	return neighborsStr
}

func formatMatchPrefixes(match *models.BgpRoutePolicyPrefixMatch) string {
	if match == nil || len(match.Prefixes) == 0 {
		return ""
	}
	var prefixes []string
	for _, p := range match.Prefixes {
		prefixes = append(prefixes, fmt.Sprintf("%s (%d..%d)", p.Cidr, p.PrefixLenMin, p.PrefixLenMax))
	}
	prefixesStr := formatStringArray(prefixes)
	if len(prefixes) > 1 {
		return fmt.Sprintf("(%s) %s", match.Type, prefixesStr)
	}
	return prefixesStr
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
func decodeBgpCapabilities(caps []*models.BgpCapabilities) ([]bgppacket.ParameterCapabilityInterface, error) {
	decodedCaps := make([]bgppacket.ParameterCapabilityInterface, len(caps))
	for i, cap := range caps {
		bin, err := base64.StdEncoding.DecodeString(cap.Capabilities)
		if err != nil {
			return decodedCaps, fmt.Errorf("could not decode from base64 to bytes %s: %w", cap.Capabilities, err)
		}
		decodedCap, err := bgppacket.DecodeCapability(bin)
		if err != nil {
			return decodedCaps, fmt.Errorf("could not decode from bytes to capability %s: %w", cap.Capabilities, err)
		}
		decodedCaps[i] = decodedCap
	}

	return decodedCaps, nil
}
func printLocalRemoteCaps(w io.Writer, localCaps, remoteCaps []bgppacket.ParameterCapabilityInterface) {
	caps := []bgppacket.ParameterCapabilityInterface{}
	caps = append(caps, localCaps...)
	for _, cap := range remoteCaps {
		if capslookup(cap, caps) == nil {
			caps = append(caps, cap)
		}
	}
	sort.Slice(caps, func(i, j int) bool {
		return caps[i].Code() < caps[j].Code()
	})

	mCapHeader := false
	for _, cap := range caps {
		support := determineSupport(cap, localCaps, remoteCaps)
		localCap := capslookup(cap, localCaps)
		remoteCap := capslookup(cap, remoteCaps)

		if cap.Code() == bgppacket.BGP_CAP_MULTIPROTOCOL && !mCapHeader {
			m := cap.(*bgppacket.CapMultiProtocol)
			fmt.Fprintf(w, "\t%s:\n", m.Code())
			mCapHeader = true
		}

		if formatter, found := capabilityFormatters[cap.Code()]; found {
			formatter(w, cap, support, localCap, remoteCap)
		} else {
			formatDefaultCap(w, cap, support, localCap, remoteCap)
		}
	}
}

func determineSupport(cap bgppacket.ParameterCapabilityInterface, localCaps, remoteCaps []bgppacket.ParameterCapabilityInterface) string {
	var support string
	if capslookup(cap, localCaps) != nil {
		support += "advertised"
	}
	if capslookup(cap, remoteCaps) != nil {
		if len(support) != 0 {
			support += " and "
		}
		support += "received"
	}
	return support
}

// capabilityFormatter defines the function signature for a capability-specific printer.
type capabilityFormatter func(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface)

// capabilityFormatters is a registry mapping BGP capability codes to their specific formatting functions.
var capabilityFormatters = map[bgppacket.BGPCapabilityCode]capabilityFormatter{
	bgppacket.BGP_CAP_MULTIPROTOCOL:               formatMultiProtocolCap,
	bgppacket.BGP_CAP_GRACEFUL_RESTART:            formatGracefulRestartCap,
	bgppacket.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART: formatLongLivedGracefulRestartCap,
	bgppacket.BGP_CAP_EXTENDED_NEXTHOP:            formatExtendedNexthopCap,
	bgppacket.BGP_CAP_ADD_PATH:                    formatAddPathCap,
	bgppacket.BGP_CAP_FQDN:                        formatFQDNCap,
	bgppacket.BGP_CAP_SOFT_VERSION:                formatSoftwareVersionCap,
}

func formatMultiProtocolCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	m := cap.(*bgppacket.CapMultiProtocol)
	fmt.Fprintf(w, "\t\t%s: %s\n", m.CapValue, support)
}

func formatCapabilityWithDetails(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface,
	handler func(io.Writer, bgppacket.ParameterCapabilityInterface)) {

	caps := []struct {
		cap   bgppacket.ParameterCapabilityInterface
		label string
	}{
		{localCap, "local"},
		{remoteCap, "remote"},
	}
	fmt.Fprintf(w, "\t%s: %s\n", cap.Code(), support)
	for _, item := range caps {
		if item.cap != nil {
			fmt.Fprintf(w, "\t\t%s:\n", item.label)
			handler(w, item.cap)
		}
	}
}

func formatGracefulRestartCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	formatCapabilityWithDetails(w, cap, support, localCap, remoteCap, func(w io.Writer, c bgppacket.ParameterCapabilityInterface) {
		g := c.(*bgppacket.CapGracefulRestart)
		if s := parseGracefulRestartCap(g); len(strings.TrimSpace(s)) > 0 {
			fmt.Fprintf(w, " %s", s)
		}
	})
}

func formatLongLivedGracefulRestartCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	formatCapabilityWithDetails(w, cap, support, localCap, remoteCap, func(w io.Writer, c bgppacket.ParameterCapabilityInterface) {
		g := c.(*bgppacket.CapLongLivedGracefulRestart)
		if s := parseLongLivedGracefulRestartCap(g); len(strings.TrimSpace(s)) > 0 {
			fmt.Fprintf(w, " %s", s)
		}
	})
}

func formatExtendedNexthopCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	formatCapabilityWithDetails(w, cap, support, localCap, remoteCap, func(w io.Writer, c bgppacket.ParameterCapabilityInterface) {
		e := c.(*bgppacket.CapExtendedNexthop)
		if s := parseExtendedNexthopCap(e); len(strings.TrimSpace(s)) > 0 {
			fmt.Fprintf(w, " %s", s)
		}
	})
}

func formatAddPathCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	formatCapabilityWithDetails(w, cap, support, localCap, remoteCap, func(w io.Writer, c bgppacket.ParameterCapabilityInterface) {
		for _, item := range c.(*bgppacket.CapAddPath).Tuples {
			fmt.Fprintf(w, "\t\t\t%s: %s\n", item.RouteFamily, item.Mode)
		}
	})
}

func formatFQDNCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	formatCapabilityWithDetails(w, cap, support, localCap, remoteCap, func(w io.Writer, c bgppacket.ParameterCapabilityInterface) {
		fqdn := c.(*bgppacket.CapFQDN)
		fmt.Fprintf(w, "\t\t\tname: %s\n\t\t\tdomain: %s\n", fqdn.HostName, fqdn.DomainName)
	})
}

func formatSoftwareVersionCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	formatCapabilityWithDetails(w, cap, support, localCap, remoteCap, func(w io.Writer, c bgppacket.ParameterCapabilityInterface) {
		version := c.(*bgppacket.CapSoftwareVersion)
		fmt.Fprintf(w, "\t\t\t%s\n", version.SoftwareVersion)
	})
}

func formatDefaultCap(w io.Writer, cap bgppacket.ParameterCapabilityInterface, support string, localCap, remoteCap bgppacket.ParameterCapabilityInterface) {
	formatCapabilityWithDetails(w, cap, support, localCap, remoteCap, func(w io.Writer, c bgppacket.ParameterCapabilityInterface) {
		fmt.Fprintf(w, "\t\t\t%s\n", c.Code())
	})
}

func capslookup(val bgppacket.ParameterCapabilityInterface, l []bgppacket.ParameterCapabilityInterface) bgppacket.ParameterCapabilityInterface {
	for _, v := range l {
		if v.Code() == val.Code() {
			if v.Code() == bgppacket.BGP_CAP_MULTIPROTOCOL {
				lhs := v.(*bgppacket.CapMultiProtocol).CapValue
				rhs := val.(*bgppacket.CapMultiProtocol).CapValue
				if lhs == rhs {
					return v
				}
				continue
			}
			return v
		}
	}
	return nil
}

func parseGracefulRestartCap(g *bgppacket.CapGracefulRestart) string {
	grStr := "\t\t\t"
	if len(g.Tuples) > 0 {
		grStr += fmt.Sprintf("restart time: %d sec", g.Time)
	}
	if g.Flags&0x08 > 0 {
		if len(strings.TrimSpace(grStr)) > 0 {
			grStr += ", "
		}
		grStr += "restart flag set"
	}
	if g.Flags&0x04 > 0 {
		if len(strings.TrimSpace(grStr)) > 0 {
			grStr += ", "
		}
		grStr += "notification flag set"
	}

	if len(grStr) > 0 {
		grStr += "\n"
	}
	for _, t := range g.Tuples {
		grStr += fmt.Sprintf("\t\t\t%s", bgppacket.AfiSafiToRouteFamily(t.AFI, t.SAFI))
		if t.Flags == 0x80 {
			grStr += ", forward flag set"
		}
		grStr += "\n"
	}
	return grStr
}

func parseLongLivedGracefulRestartCap(g *bgppacket.CapLongLivedGracefulRestart) string {
	var llgrStr strings.Builder
	for _, t := range g.Tuples {
		fmt.Fprintf(&llgrStr, "\t\t\t%s, restart time %d sec", bgppacket.AfiSafiToRouteFamily(t.AFI, t.SAFI), t.RestartTime)
		if t.Flags == 0x80 {
			llgrStr.WriteString(", forward flag set")
		}
		llgrStr.WriteString("\n")
	}
	return llgrStr.String()
}

func parseExtendedNexthopCap(e *bgppacket.CapExtendedNexthop) string {
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
		line := fmt.Sprintf("\t\t\tnlri: %s, nexthop: %s\n", bgppacket.AfiSafiToRouteFamily(t.NLRIAFI, uint8(t.NLRISAFI)), nhafi)
		lines = append(lines, line)
	}
	return strings.Join(lines, "")
}
