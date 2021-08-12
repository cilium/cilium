// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/vishvananda/netlink"

	"github.com/spf13/cobra"
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
	command.AddJSONOutput(encryptFlushCmd)
}
