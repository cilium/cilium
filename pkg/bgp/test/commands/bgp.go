// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgp/agent"
	"github.com/cilium/cilium/pkg/bgp/api"
)

const (
	routerASNFlag      = "router-asn"
	routerASNFlagShort = "r"
)

func BGPScriptCmds(bgpMgr agent.BGPRouterManager) map[string]script.Cmd {
	return map[string]script.Cmd{
		"bgp/route-policies": BGPPRoutePolicies(bgpMgr),
	}
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
