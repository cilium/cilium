// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// lrpCmd represents the lrp command
var lrpCmd = &cobra.Command{
	Use:   "lrp",
	Short: "Manage local redirect policies",
}

func init() {
	rootCmd.AddCommand(lrpCmd)
}
