// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
)

// policyCacheGetCmd represents the policy selectors command
var policyCacheGetCmd = &cobra.Command{
	Use:   "selectors",
	Short: "Display cached information about selectors",
	Run: func(cmd *cobra.Command, args []string) {
		if resp, err := client.PolicyCacheGet(); err != nil {
			Fatalf("Cannot get policy: %s\n", err)
		} else if command.OutputOption() {
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
	command.AddOutputOption(policyCacheGetCmd)
}
