// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

var verbosePolicySelectors bool

// policyCacheGetCmd represents the policy selectors commands
var policyCacheGetCmd = func(name, description string, f func() (models.SelectorCache, error)) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: description,
		Run: func(cmd *cobra.Command, args []string) {
			if resp, err := f(); err != nil {
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
					lbls := constructLabelArrayListFromAPIType(mapping.Labels)

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
}

func getNameAndNamespaceFromLabels(list labels.LabelArrayList) string {
	var sb strings.Builder
	for _, lbls := range list {
		ns := lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sconst.PolicyLabelNamespace)
		if ns != "" {
			if sb.Len() > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(ns)
			sb.WriteRune('/')
			sb.WriteString(lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sconst.PolicyLabelName))
		}
	}
	return sb.String()
}

func constructLabelArrayListFromAPIType(in models.LabelArrayList) labels.LabelArrayList {
	list := make(labels.LabelArrayList, 0, len(in))
	for _, la := range in {
		lbls := make(labels.LabelArray, 0, len(la))
		for _, l := range la {
			lbls = append(lbls, labels.Label{
				Key:    l.Key,
				Value:  l.Value,
				Source: l.Source,
			})
		}
		list = append(list, lbls)
	}
	return list
}

func init() {
	for _, c := range []struct {
		name        string
		description string
		f           func() (models.SelectorCache, error)
	}{
		{
			name:        "selectors",
			description: "Display cached information about selectors",
			f:           func() (models.SelectorCache, error) { return client.PolicyCacheGet() },
		},
		{
			name:        "subject-selectors",
			description: "Display cached information about subject selectors",
			f:           func() (models.SelectorCache, error) { return client.SubjectPolicySelectorsGet() },
		},
	} {
		cmd := policyCacheGetCmd(c.name, c.description, c.f)
		cmd.Flags().BoolVarP(&verbosePolicySelectors, "verbose", "v", false, "Show the full labels")
		PolicyCmd.AddCommand(cmd)
		command.AddOutputOption(cmd)
	}
}
