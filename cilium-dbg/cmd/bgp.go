// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "github.com/spf13/cobra"

// BgpCmd represents the bgp command
var BgpCmd = &cobra.Command{
	Use:   "bgp",
	Short: "Access to BGP control plane",
}

func init() {
	RootCmd.AddCommand(BgpCmd)
}
