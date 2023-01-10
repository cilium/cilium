// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
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
		netlink.XfrmPolicyFlush()
		netlink.XfrmStateFlush(netlink.XFRM_PROTO_ESP)
	},
}

func init() {
	encryptCmd.AddCommand(encryptFlushCmd)
	command.AddOutputOption(encryptFlushCmd)
}
