// Copyright 2019 Authors of Cilium
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
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

// policyGetCmd represents the policy_get command
var policyCacheGetCmd = &cobra.Command{
	Use:   "selectors",
	Short: "Display cached information about selectors",
	Run: func(cmd *cobra.Command, args []string) {
		if resp, err := client.PolicyCacheGet(); err != nil {
			Fatalf("Cannot get policy: %s\n", err)
		} else if command.OutputJSON() {
			if err := command.PrintOutput(resp); err != nil {
				os.Exit(1)
			}
		} else if resp != nil {
			w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

			fmt.Fprintf(w, "SELECTOR\tUSERS\tIDENTITIES\n")
			for _, mapping := range resp {
				first := true
				fmt.Fprintf(w, "%s", mapping.Selector)
				fmt.Fprintf(w, "\t%d", mapping.Users)
				if len(mapping.Identities) == 0 {
					fmt.Fprintf(w, "\t\n")
				}
				for _, idty := range mapping.Identities {
					if first {
						fmt.Fprintf(w, "\t%d\t\n", idty)
						first = false
					} else {
						fmt.Fprintf(w, "\t\t%d\t\n", idty)
					}
				}
			}

			w.Flush()
		}
	},
}

func init() {
	policyCmd.AddCommand(policyCacheGetCmd)
	command.AddJSONOutput(policyCacheGetCmd)
}
