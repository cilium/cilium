// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
)

var encryptFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flushes the current IPsec state",
	Long:  "Will cause a short connectivity disruption",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium encrypt flush")
		runXFRMFlush()
	},
}

func runXFRMFlush() {
	confirmationMsg := "Flushing all XFRM states and policies can lead to transient " +
		"connectivity interruption and plain-text pod-to-pod traffic."
	if !confirmXFRMCleanup(confirmationMsg) {
		return
	}
	netlink.XfrmPolicyFlush()
	netlink.XfrmStateFlush(netlink.XFRM_PROTO_ESP)
	fmt.Println("All XFRM states and policies have been deleted.")
}

func confirmXFRMCleanup(msg string) bool {
	if force {
		return true
	}
	var res string
	fmt.Printf("%s Do you want to continue? [y/N] ", msg)
	fmt.Scanln(&res)
	return res == "y"
}

func init() {
	encryptFlushCmd.Flags().BoolVarP(&force, forceFlagName, "f", false, "Skip confirmation")
	CncryptCmd.AddCommand(encryptFlushCmd)
	command.AddOutputOption(encryptFlushCmd)
}
