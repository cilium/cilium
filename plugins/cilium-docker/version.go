// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		getVersion(cmd, args)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

func getVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("%s\n", version.Version)
}
