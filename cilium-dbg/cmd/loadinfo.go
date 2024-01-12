// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/loadinfo"
)

// LoadInfoCmd represents the loadinfo command
var LoadInfoCmd = &cobra.Command{
	Use:   "loadinfo",
	Short: "Show load information",
	Run: func(cmd *cobra.Command, args []string) {
		loadinfo.LogCurrentSystemLoad(printFunc)
	},
}

func printFunc(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	fmt.Println()
}

func init() {
	RootCmd.AddCommand(LoadInfoCmd)
}
