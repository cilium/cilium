// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	errNoSysdump = "cilium-dbg sysdump cannot perform this action, you need a different tool.\nSee https://docs.cilium.io/en/stable/operations/troubleshooting/#reporting-a-problem\n"

	sysdumpCmd = &cobra.Command{
		Use:   "sysdump",
		Short: "Provide instructions on dumping cluster-wide system state",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stderr, "%s\n", errNoSysdump)
			os.Exit(1)
		},
	}
)

func init() {
	RootCmd.AddCommand(sysdumpCmd)
}
