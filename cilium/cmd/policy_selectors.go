// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

var verbosePolicySelectors bool

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
			// Sort to keep output stable
			sort.Slice(resp, func(i, j int) bool {
				return resp[i].Selector < resp[j].Selector
			})
			fmt.Fprintf(w, "SELECTOR\tLABELS\tUSERS\tIDENTITIES\n")

			for _, mapping := range resp {
				lbls := constructLabelsArrayFromAPIType(mapping.Labels)

				first := true
				fmt.Fprintf(w, "%s", mapping.Selector)
				if verbosePolicySelectors {
					var lstr string
					if len(lbls) != 0 {
						lstr = lbls.Sort().String()
					}
					fmt.Fprintf(w, "\t%s", lstr)
				} else {
					fmt.Fprintf(w, "\t%s", getNameAndNamespaceFromLabels(lbls))
				}
				fmt.Fprintf(w, "\t%d", mapping.Users)
				if len(mapping.Identities) == 0 {
					fmt.Fprintf(w, "\t\n")
				}
				for _, idty := range mapping.Identities {
					if first {
						fmt.Fprintf(w, "\t%d\t\n", idty)
						first = false
					} else {
						fmt.Fprintf(w, "\t\t\t%d\t\n", idty)
					}
				}
			}

			w.Flush()
		}
	},
}

func getNameAndNamespaceFromLabels(lbls labels.LabelArray) string {
	ns := lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sconst.PolicyLabelNamespace)
	if ns == "" {
		return ""
	}
	return ns + "/" + lbls.Get(labels.LabelSourceK8sKeyPrefix+k8sconst.PolicyLabelName)
}

func constructLabelsArrayFromAPIType(in interface{}) labels.LabelArray {
	lbls, ok := in.(labels.LabelArray)
	if !ok {
		return nil
	}
	return lbls
}

func init() {
	policyCacheGetCmd.Flags().BoolVarP(&verbosePolicySelectors, "verbose", "v", false, "Show the full labels")
	PolicyCmd.AddCommand(policyCacheGetCmd)
	command.AddOutputOption(policyCacheGetCmd)
}
