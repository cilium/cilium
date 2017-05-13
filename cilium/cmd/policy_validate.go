// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// policyValidateCmd represents the policy_validate command
var policyValidateCmd = &cobra.Command{
	Use:    "validate <path>",
	Short:  "Validate a policy",
	PreRun: requirePath,
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		if ruleList, err := loadPolicy(path); err != nil {
			Fatalf("Validation of policy has failed: %s\n", err)
		} else {
			fmt.Printf("All policy elements are valid.\n")

			if printPolicy {
				jsonPolicy, err := json.MarshalIndent(ruleList, "", "  ")
				if err != nil {
					Fatalf("Cannot marshal policy: %s\n", err)
				}
				fmt.Printf("%s", string(jsonPolicy))
			}
		}
	},
}

func init() {
	policyCmd.AddCommand(policyValidateCmd)
	policyValidateCmd.Flags().BoolVarP(&printPolicy, "print", "", false, "Print policy after validation")

}
