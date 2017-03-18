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
	"fmt"

	"github.com/spf13/cobra"
)

var printPolicy bool

// policyImportCmd represents the policy_import command
var policyImportCmd = &cobra.Command{
	Use:   "import <path>",
	Short: "Import security policy",
	Example: `  cilium policy import ~/app.policy
  cilium policy import ./policies/app/`,
	PreRun: requirePath,
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		if node, err := loadPolicy(path); err != nil {
			Fatalf("Cannot parse policy %s: %s\n", path, err)
		} else {
			log.Debugf("Constructed policy object for import %+v", node)

			// Ignore request if no policies have been found
			if node == nil {
				return
			}

			jsonPolicy := node.JSONMarshal()
			if resp, err := client.PolicyPut(node.Name, jsonPolicy); err != nil {
				Fatalf("Cannot import policy %s: %s\n", path, err)
			} else if printPolicy {
				fmt.Printf("%s\n", resp)
			}
		}
	},
}

func init() {
	policyCmd.AddCommand(policyImportCmd)
	policyImportCmd.Flags().BoolVarP(&printPolicy, "print", "", false, "Print policy after import")
}
