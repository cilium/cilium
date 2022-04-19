// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
)

var confirmDeleteAll bool

// policyDeleteCmd represents the policy_delete command
var policyDeleteCmd = &cobra.Command{
	Use:   "delete [<labels>]",
	Short: "Delete policy rules",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && !confirmDeleteAll {
			Fatalf("Please use --all flag to delete all policies")
		}

		if resp, err := client.PolicyDelete(args); err != nil {
			Fatalf("Cannot delete policy: %s\n", err)
		} else if command.OutputOption() {
			if err := command.PrintOutput(resp); err != nil {
				os.Exit(1)
			}
		} else {
			fmt.Printf("Revision: %d\n", resp.Revision)
		}
	},
}

func init() {
	policyCmd.AddCommand(policyDeleteCmd)
	policyDeleteCmd.Flags().BoolVarP(&confirmDeleteAll, "all", "", false, "Delete all policies")
	command.AddOutputOption(policyDeleteCmd)
}
