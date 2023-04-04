// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/srv6map"

	"github.com/spf13/cobra"
)

const (
	srv6PolicyListUsage = "List SRv6 policy entries."
)

type srv6Policy struct {
	VRFID    uint32
	DestCIDR string
	SID      string
}

var bpfSRv6PolicyListCmd = &cobra.Command{
	Use:     "policy",
	Aliases: []string{"pol"},
	Short:   "List SRv6 policy entries",
	Long:    srv6PolicyListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 policy")

		if err := srv6map.OpenPolicyMaps(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find SRv6 policy maps")
				return
			}

			Fatalf("Cannot open SRv6 policy maps: %s", err)
		}

		bpfPolicyList := []srv6Policy{}
		parse := func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			bpfPolicyList = append(bpfPolicyList, srv6Policy{
				VRFID:    key.VRFID,
				DestCIDR: key.DestCIDR.String(),
				SID:      val.SID.String(),
			})
		}

		if err := srv6map.SRv6PolicyMap4.IterateWithCallback4(parse); err != nil {
			Fatalf("Error dumping contents of the IPv4 SRv6 policy map: %s\n", err)
		}
		if err := srv6map.SRv6PolicyMap6.IterateWithCallback6(parse); err != nil {
			Fatalf("Error dumping contents of the IPv6 SRv6 policy map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfPolicyList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfPolicyList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printSRv6PolicyList(bpfPolicyList)
		}
	},
}

func printSRv6PolicyList(policyList []srv6Policy) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "VRF ID\tDestination CIDR\tSID")
	for _, policy := range policyList {
		fmt.Fprintf(w, "%d\t%s\t%s\n", policy.VRFID, policy.DestCIDR, policy.SID)
	}

	w.Flush()
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6PolicyListCmd)
	command.AddOutputOption(bpfSRv6PolicyListCmd)
}
