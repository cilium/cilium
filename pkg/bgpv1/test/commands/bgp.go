// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/api"
)

const (
	peerFlag      = "peer"
	peerFlagShort = "p"

	routerASNFlag      = "router-asn"
	routerASNFlagShort = "r"
)

func BGPScriptCmds(bgpMgr agent.BGPRouterManager) map[string]script.Cmd {
	return map[string]script.Cmd{
		"bgp/peers":          BGPPPeersCmd(bgpMgr),
		"bgp/routes":         BGPPRoutesCmd(bgpMgr),
		"bgp/route-policies": BGPPRoutePolicies(bgpMgr),
	}
}

func BGPPPeersCmd(bgpMgr agent.BGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP peers on Cilium",
			Flags: func(fs *pflag.FlagSet) {
				addOutFileFlag(fs)
			},
			Detail: []string{
				"List current state of all BGP peers configured in Cilium BGP Control Plane.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(*script.State) (stdout, stderr string, err error) {
				tw, buf, f, err := getCmdTabWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				peers, err := bgpMgr.GetPeers(s.Context())
				if err != nil {
					return "", "", err
				}
				api.PrintBGPPeersTable(tw, peers, false)

				return buf.String(), "", err
			}, nil
		},
	)
}

func BGPPRoutesCmd(bgpMgr agent.BGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP routes on Cilium",
			Args:    "[available|advertised] [afi] [safi]",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP(peerFlag, peerFlagShort, "", "IP address of the peer. If provided, routes advertised to the specified peer are listed.")
				fs.Uint32P(routerASNFlag, routerASNFlagShort, 0, "ASN number of the Cilium router instance. Lists routes of all instances if omitted.")
				addOutFileFlag(fs)
			},
			Detail: []string{
				"List routes in the BGP Control Plane's RIBs",
				"",
				"'available' lists routes from the local RIB, 'advertised' lists routes from the RIB-OUT of BGP peer(s).",
				"When none of them is provided, lists 'available' routes",
				"",
				"'afi' is Address Family Indicator, defaults to 'ipv4'.",
				"'safi' is Subsequent Address Family Identifier, defaults to 'unicast'.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			peer, err := s.Flags.GetString(peerFlag)
			if err != nil {
				return nil, err
			}
			asn, err := s.Flags.GetUint32(routerASNFlag)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				tw, buf, f, err := getCmdTabWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				params := restapi.GetBgpRoutesParams{
					TableType: "loc-rib",
					Afi:       "ipv4",
					Safi:      "unicast",
				}
				if len(args) > 0 && args[0] == "advertised" {
					params.TableType = "adj-rib-out"
				}
				if len(args) > 1 && args[1] != "" {
					params.Afi = args[1]
				}
				if len(args) > 2 && args[2] != "" {
					params.Safi = args[2]
				}
				if peer != "" {
					params.Neighbor = &peer
				}
				if asn != 0 {
					asn64 := int64(asn)
					params.RouterAsn = &asn64
				}
				routes, err := bgpMgr.GetRoutes(s.Context(), params)
				if err != nil {
					return "", "", err
				}
				err = api.PrintBGPRoutesTable(tw, routes, params.TableType == "adj-rib-out", false)

				return buf.String(), "", err
			}, nil
		},
	)
}

func BGPPRoutePolicies(bgpMgr agent.BGPRouterManager) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List BGP route policies on Cilium",
			Flags: func(fs *pflag.FlagSet) {
				fs.Uint32P(routerASNFlag, routerASNFlagShort, 0, "ASN number of the Cilium router instance. Lists policies of all instances if omitted.")
				addOutFileFlag(fs)
			},
			Detail: []string{
				"Lists route policies configured in Cilium BGP Control Plane.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			asn, err := s.Flags.GetUint32(routerASNFlag)
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				tw, buf, f, err := getCmdTabWriter(s)
				if err != nil {
					return "", "", err
				}
				if f != nil {
					defer f.Close()
				}

				params := restapi.GetBgpRoutePoliciesParams{}
				if asn != 0 {
					asn64 := int64(asn)
					params.RouterAsn = &asn64
				}
				policies, err := bgpMgr.GetRoutePolicies(s.Context(), params)
				if err != nil {
					return "", "", err
				}
				api.PrintBGPRoutePoliciesTable(tw, policies)

				return buf.String(), "", err
			}, nil
		},
	)
}
