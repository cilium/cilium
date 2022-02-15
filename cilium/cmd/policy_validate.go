// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var policyVerbose bool

// policyValidateCmd represents the policy_validate command
var policyValidateCmd = &cobra.Command{
	Use:    "validate <path>",
	Short:  "Validate a policy",
	PreRun: requirePath,
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		if ruleList, err := loadPolicy(path); err != nil {
			Fatalf("Validation of policy %s has failed: %s\n", path, err)
		} else {
			for _, r := range ruleList {
				if err := r.Sanitize(); err != nil {
					Fatalf("Validation of policy %s has failed: %s\n", path, err)
				}
			}
			if policyVerbose {
				fmt.Printf("All policy elements in %s are valid.\n", path)
			}

			if printPolicy {
				jsonPolicy, err := json.MarshalIndent(ruleList, "", "  ")
				if err != nil {
					Fatalf("Cannot marshal policy %s: %s\n", path, err)
				}
				fmt.Printf("%s", jsonPolicy)
			}
		}
	},
}

func init() {
	policyCmd.AddCommand(policyValidateCmd)
	policyValidateCmd.Flags().BoolVarP(&printPolicy, "print", "", false, "Print policy after validation")
	policyValidateCmd.Flags().BoolVarP(&policyVerbose, "verbose", "v", true, "Enable verbose output")
}
