// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var StatedbCmd = &cobra.Command{
	Use:   "statedb",
	Short: "Inspect StateDB",
}

var statedbDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump StateDB contents as JSON",
	Run: func(cmd *cobra.Command, args []string) {
		_, err := client.Statedb.GetStatedbDump(nil, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	StatedbCmd.AddCommand(statedbDumpCmd)
	RootCmd.AddCommand(StatedbCmd)
}
