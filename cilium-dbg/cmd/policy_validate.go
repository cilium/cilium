// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/policy/api"
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
			valid := true
			for _, r := range ruleList {
				if err := r.Sanitize(); err != nil {
					valid = false
					if errors.Is(err, api.ErrFromToNodesRequiresNodeSelectorOption) {
						// Don't error out as this can't be validated client-side
						fmt.Printf("Validation of policy %s has been skipped in the client, further validation will occur server-side.\n", path)
					} else {
						Fatalf("Validation of policy %s has failed: %s\n", path, err)
					}
				}
			}
			if policyVerbose && valid {
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
	PolicyCmd.AddCommand(policyValidateCmd)
	policyValidateCmd.Flags().BoolVarP(&printPolicy, "print", "", false, "Print policy after validation")
	policyValidateCmd.Flags().BoolVarP(&policyVerbose, "verbose", "v", true, "Enable verbose output")
}
