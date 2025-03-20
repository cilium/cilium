// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/spf13/cobra"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/client/bgp"
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

	ipv4AFI     = "ipv4"
	unicastSAFI = "unicast"
)

var BgpRoutesCmd = &cobra.Command{
	Use:   "routes <available | advertised> <afi> <safi> [vrouter <asn>] [peer|neighbor <address>]",
	Short: "List routes in the BGP Control Plane's RIBs",
	Long:  "List routes in the BGP Control Plane's Routing Information Bases (RIBs)",
	Example: `  Get all IPv4 unicast routes available:
    cilium-dbg bgp routes available ipv4 unicast

  Get all IPv6 unicast routes available for a specific vrouter:
    cilium-dbg bgp routes available ipv6 unicast vrouter 65001

  Get IPv4 unicast routes advertised to a specific peer:
    cilium-dbg bgp routes advertised ipv4 unicast peer 10.0.0.1`,

	Run: func(cmd *cobra.Command, args []string) {
		var err error
		params := bgp.NewGetBgpRoutesParams()

		// parse <available | advertised> <afi> <safi
		params.TableType, params.Afi, params.Safi, args, err = parseBGPRoutesMandatoryArgs(args, command.OutputOption())
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
			params.RouterAsn = ptr.To[int64](asn)
		}

		// parse [peer|neighbor <address>]
		if params.TableType == adjRIBOutTableType && len(args) > 0 {
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
			// print peer addresses for `advertised` routes without specifying a peer
			printPeer := (params.TableType == adjRIBOutTableType) && (params.Neighbor == nil || *params.Neighbor == "")
			w := NewTabWriter()
			if err := api.PrintBGPRoutesTable(w, res.GetPayload(), printPeer, true); err != nil {
				Fatalf("failed printing BGP routes: %s\n", err)
			}
		}
	},
}

func parseBGPRoutesMandatoryArgs(args []string, silent bool) (tableType, afi, safi string, argsOut []string, err error) {
	if len(args) < 1 {
		if !silent {
			fmt.Printf("(Defaulting to `%s %s %s` routes, please see help for more options)\n\n", availableRoutesKW, ipv4AFI, unicastSAFI)
		}
		return locRIBTableType, ipv4AFI, unicastSAFI, nil, nil
	}
	switch args[0] {
	case availableRoutesKW:
		tableType = locRIBTableType
	case advertisedRoutesKW:
		tableType = adjRIBOutTableType
	default:
		err = fmt.Errorf("invalid table type discriminator `%s` (should be `%s` / `%s`)", args[0], availableRoutesKW, advertisedRoutesKW)
		return
	}

	if len(args) < 2 {
		if !silent {
			fmt.Printf("(Defaulting to `%s %s` AFI & SAFI, please see help for more options)\n\n", ipv4AFI, unicastSAFI)
		}
		return tableType, ipv4AFI, unicastSAFI, nil, nil
	}
	if types.ParseAfi(args[1]) == types.AfiUnknown {
		err = fmt.Errorf("unknown AFI %s", args[1])
		return
	}
	afi = args[1]

	if len(args) < 3 {
		if !silent {
			fmt.Printf("(Defaulting to `%s` SAFI, please see help for more options)\n\n", unicastSAFI)
		}
		return tableType, afi, unicastSAFI, nil, nil
	}
	if types.ParseSafi(args[2]) == types.SafiUnknown {
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
	if args[0] != peerKW && args[0] != neighborKW {
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

func init() {
	BgpCmd.AddCommand(BgpRoutesCmd)
	command.AddOutputOption(BgpRoutesCmd)
}
