// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "github.com/spf13/cobra"

// CgroupsCmd represents the cgroups command
var CgroupsCmd = &cobra.Command{
	Use:   "cgroups",
	Short: "Cgroup metadata",
}

func init() {
	RootCmd.AddCommand(CgroupsCmd)
}
