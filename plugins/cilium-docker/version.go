// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2019 Authors of Cilium

package main

import (
	"fmt"

	"github.com/cilium/cilium/pkg/version"

	"github.com/spf13/cobra"
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
