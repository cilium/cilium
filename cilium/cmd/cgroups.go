// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "github.com/spf13/cobra"

// cgroupsCmd represents the cgroups command
var cgroupsCmd = &cobra.Command{
	Use:   "cgroups",
	Short: "Cgroup metadata",
}

func init() {
	rootCmd.AddCommand(cgroupsCmd)
}
