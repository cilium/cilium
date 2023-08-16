// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	bgppacket "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/spf13/cobra"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/api/v1/client/bgp"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/command"
)

const (
	availableRoutesKW  = "available"
	advertisedRoutesKW = "advertised"
	vRouterKW          = "vrouter"
	peerKW             = "peer"
	neighborKW         = "neighbor"

	locRIBTableType    = "loc-rib"
	adjRIBOutTableType = "adj-rib-out"
)

var BgpRoutesCmd = &cobra.Command{
	Use:   "routes <available | advertised> <afi> <safi> [vrouter <asn>] [peer|neighbor <address>]",
	Short: "List routes in the BGP Control Plane's RIBs",
	Long:  "List routes in the BGP Control Plane's Routing Information Bases (RIBs)",
	Example: `  Get all IPv4 unicast routes available:
    cilium bgp routes available ipv4 unicast

  Get all IPv6 unicast routes available for a specific vrouter:
    cilium bgp routes available ipv6 unicast vrouter 65001

  Get IPv4 unicast routes advertised to a specific peer:
    cilium bgp routes advertised ipv4 unicast peer 10.0.0.1`,

	Run: func(cmd *cobra.Command, args []string) {
		var err error
		params := bgp.NewGetBgpRoutesParams()

		// parse <available | advertised> <afi> <safi
		params.TableType, params.Afi, params.Safi, args, err = parseBGPRoutesMandatoryArgs(args)
		if err != nil {
			Fatalf("invalid argument: %s\n", err)
		}

		// parse [vrouter <asn>]
		if len(args) > 0 && args[0] == vRouterKW {
			var asn int64
			asn, args, err = parseVRouterASN(args)
			if err != nil {
				Fatalf("failed to parse vrouter ASN: %s\n", err)
			}
			params.RouterAsn = pointer.Int64(asn)
		}

		// parse [peer|neighbor <address>]
		if params.TableType == adjRIBOutTableType {
			addr, err := parseBGPPeerAddr(args)
			if err != nil {
				Fatalf("failed to parse peer address: %s\n", err)
			}
			params.Neighbor = &addr
		}

		// retrieve the routes
		res, err := client.Bgp.GetBgpRoutes(params)
		if err != nil {
			disabledErr := bgp.NewGetBgpRoutesDisabled()
			if errors.As(err, &disabledErr) {
				fmt.Println("BGP Control Plane is disabled")
				return
			}
			Fatalf("failed retrieving routes: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(res.GetPayload()); err != nil {
				Fatalf("failed getting output in JSON: %s\n", err)
			}
		} else {
			printBGPRoutesTable(res.GetPayload())
		}
	},
}

func parseBGPRoutesMandatoryArgs(args []string) (tableType, afi, safi string, argsOut []string, err error) {
	if len(args) < 1 {
		err = fmt.Errorf("missing `available` or `advertised` parameter")
		return
	}
	switch args[0] {
	case availableRoutesKW:
		tableType = locRIBTableType
	case advertisedRoutesKW:
		tableType = adjRIBOutTableType
	default:
		err = fmt.Errorf("invalid table type discriminator `%s` (should be `available` / `advertised`)", args[0])
		return
	}

	if len(args) < 2 {
		err = fmt.Errorf("missing AFI value (e.g. `ipv4`)")
		return
	}
	if api.ToAgentAfi(args[1]) == types.AfiUnknown {
		err = fmt.Errorf("unknown AFI %s", args[1])
		return
	}
	afi = args[1]

	if len(args) < 3 {
		err = fmt.Errorf("missing SAFI value (e.g. `unicast`)")
		return
	}
	if api.ToAgentSafi(args[2]) == types.SafiUnknown {
		err = fmt.Errorf("unknown SAFI %s", args[2])
		return
	}
	safi = args[2]

	argsOut = args[3:] // re-slice processed arguments
	return
}

func parseVRouterASN(args []string) (asn int64, argsOut []string, err error) {
	if len(args) == 0 || args[0] != vRouterKW {
		err = fmt.Errorf("missing `vrouter` parameter")
		return
	}

	if len(args) < 2 {
		err = fmt.Errorf("missing vrouter ASN value")
		return
	}
	asn, err = strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid vrouter ASN: %w", err)
		return
	}

	argsOut = args[2:] // re-slice processed arguments
	return
}

func parseBGPPeerAddr(args []string) (string, error) {
	// also accept "neighbor" keyword as it is commonly interchanged with "peer"
	if len(args) == 0 || (args[0] != peerKW && args[0] != neighborKW) {
		return "", fmt.Errorf("missing `peer` parameter")
	}

	if len(args) < 2 {
		return "", fmt.Errorf("missing peer IP address")
	}
	addr, err := netip.ParseAddr(args[1])
	if err != nil {
		return "", fmt.Errorf("invalid peer IP address: %w", err)
	}

	return addr.String(), nil
}

func printBGPRoutesTable(routes []*models.BgpRoute) {
	// sort first by ASN and then by prefix
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].RouterAsn < routes[j].RouterAsn || routes[i].Prefix < routes[j].Prefix
	})

	// get new tab writer with predefined defaults
	w := NewTabWriter()
	fmt.Fprintln(w, "VRouter\tPrefix\tNextHop\tAge\tAttrs")

	for _, route := range routes {
		r, err := api.ToAgentRoute(route)
		if err != nil {
			Fatalf("failed to decode API route: %s\n", err)
		}
		for _, path := range r.Paths {
			fmt.Fprintf(w, "%d\t", route.RouterAsn)
			fmt.Fprintf(w, "%s\t", path.NLRI)
			fmt.Fprintf(w, "%s\t", nextHopFromPathAttributes(path.PathAttributes))
			fmt.Fprintf(w, "%s\t", time.Duration(path.AgeNanoseconds).Round(time.Second))
			fmt.Fprintf(w, "%s\t", path.PathAttributes)
			fmt.Fprintf(w, "\n")
		}
	}
	w.Flush()
}

func nextHopFromPathAttributes(pathAttributes []bgppacket.PathAttributeInterface) string {
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

func init() {
	BgpCmd.AddCommand(BgpRoutesCmd)
	command.AddOutputOption(BgpRoutesCmd)
}
