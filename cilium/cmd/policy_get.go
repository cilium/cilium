// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
)

// policyGetCmd represents the policy_get command
var policyGetCmd = &cobra.Command{
	Use:   "get [<labels>]",
	Short: "Display policy node information",
	Run: func(cmd *cobra.Command, args []string) {
		if resp, err := client.PolicyGet(args); err != nil {
			Fatalf("Cannot get policy: %s\n", err)
		} else if command.OutputOption() {
			if err := command.PrintOutput(resp); err != nil {
				os.Exit(1)
			}
		} else if resp != nil {
			fmt.Printf("%s\nRevision: %d\n", resp.Policy, resp.Revision)
		}
	},
}

func init() {
	policyCmd.AddCommand(policyGetCmd)
	command.AddOutputOption(policyGetCmd)
}
