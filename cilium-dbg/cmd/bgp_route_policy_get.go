// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/client/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/api"
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
			w := NewTabWriter()
			api.PrintBGPRoutePoliciesTable(w, res.GetPayload())
		}
	},
}

func init() {
	BgpCmd.AddCommand(BgpRoutePoliciesCmd)
	command.AddOutputOption(BgpRoutePoliciesCmd)
}
