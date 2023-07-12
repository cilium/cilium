// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// LRPCmd represents the lrp command
var LRPCmd = &cobra.Command{
	Use:   "lrp",
	Short: "Manage local redirect policies",
}

func init() {
	RootCmd.AddCommand(LRPCmd)
}
