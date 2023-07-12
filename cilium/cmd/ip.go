// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// IPCmd represents the ip command
var IPCmd = &cobra.Command{
	Use:   "ip",
	Short: "Manage IP addresses and associated information",
}

func init() {
	RootCmd.AddCommand(IPCmd)
}
