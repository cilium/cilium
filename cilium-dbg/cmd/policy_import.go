// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var printPolicy bool
var replacePolicy bool
var replaceWithLabels []string

// policyImportCmd represents the policy_import command
var policyImportCmd = &cobra.Command{
	Use:   "import <path>",
	Short: "Import security policy in JSON format",
	Example: `  cilium-dbg policy import ~/policy.json
  cilium-dbg policy import ./policies/app/`,
	PreRun: requirePath,
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		if ruleList, err := loadPolicy(path); err != nil {
			Fatalf("Cannot parse policy %s: %s\n", path, err)
		} else {
			log.WithField("rule", logfields.Repr(ruleList)).Debug("Constructed policy object for import")

			// Ignore request if no policies have been found
			if len(ruleList) == 0 {
				fmt.Printf("No policy specified")
				return
			}

			for _, r := range ruleList {
				if err := r.Sanitize(); err != nil {
					Fatalf("%s", err)
				}
			}

			jsonPolicy, err := json.MarshalIndent(ruleList, "", "  ")
			if err != nil {
				Fatalf("Cannot marshal policy: %s\n", err)
			}
			if resp, err := client.PolicyReplace(string(jsonPolicy), replacePolicy, replaceWithLabels); err != nil {
				Fatalf("Cannot import policy: %s\n", err)
			} else if command.OutputOption() {
				if err := command.PrintOutput(resp); err != nil {
					os.Exit(1)
				}
			} else if printPolicy {
				fmt.Printf("%s\nRevision: %d\n", resp.Policy, resp.Revision)
			} else {
				fmt.Printf("Revision: %d\n", resp.Revision)
			}
		}
	},
}

func init() {
	PolicyCmd.AddCommand(policyImportCmd)
	policyImportCmd.Flags().BoolVarP(&printPolicy, "print", "", false, "Print policy after import")
	policyImportCmd.Flags().BoolVarP(&replacePolicy, "replace", "", false, "Replace existing policy")
	policyImportCmd.Flags().StringSliceVarP(&replaceWithLabels, "replace-with-labels", "", []string{}, "Replace existing policies that match given labels")
	command.AddOutputOption(policyImportCmd)
}
