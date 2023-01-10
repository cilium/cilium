// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var bpfTunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Tunnel endpoint map",
}

func init() {
	bpfCmd.AddCommand(bpfTunnelCmd)
}
