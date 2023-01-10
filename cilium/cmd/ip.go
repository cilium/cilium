// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// ipCmd represents the ip command
var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "Manage IP addresses and associated information",
}

func init() {
	rootCmd.AddCommand(ipCmd)
}
