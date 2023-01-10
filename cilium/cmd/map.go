// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// mapCmd represents the map command
var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Access userspace cached content of BPF maps",
}

func init() {
	rootCmd.AddCommand(mapCmd)
}
