// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// serviceCmd represents the service command
var lrpCmd = &cobra.Command{
	Use:   "lrp",
	Short: "Manage local redirect policies",
}

func init() {
	rootCmd.AddCommand(lrpCmd)
}
