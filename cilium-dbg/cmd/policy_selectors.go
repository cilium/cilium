// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gosuri/uitable"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/slices"
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
				// Sort to keep output stable
				sort.Slice(resp, func(i, j int) bool {
					return resp[i].Selector < resp[j].Selector
				})

				for _, mapping := range resp {
					table := uitable.New()
					table.Wrap = true
					table.MaxColWidth = 50000
					table.AddRow("Selector:", formatSelector(mapping.Selector))
					table.AddRow("Owners:", formatLabels(mapping.Labels))
					table.AddRow("User count:", mapping.Users)
					table.AddRow("Identities:", strings.Join(
						slices.Map(mapping.Identities, func(i int64) string {
							return strconv.FormatInt(i, 10)
						}),
						"\n",
					))
					fmt.Println(table)
					fmt.Print("\n\n")
				}
			}
		},
	}
}

func formatLabels(in models.LabelArrayList) string {
	list := constructLabelArrayListFromAPIType(in)

	var sb strings.Builder
	first := true
	for _, lbls := range list {
		if !first {
			sb.WriteRune('\n')
		} else {
			first = false
		}
		if verbosePolicySelectors {
			sb.WriteString(lbls.String())
			continue
		}

		kind := lbls.Get("io.cilium.k8s.policy.derived-from")
		ns := lbls.Get("k8s:io.cilium.k8s.policy.namespace")
		name := lbls.Get("k8s:io.cilium.k8s.policy.name")
		if kind != "" {
			sb.WriteString(kind)
			sb.WriteRune(':')
			if ns != "" {
				sb.WriteString(ns)
				sb.WriteRune('/')
			}
			sb.WriteString(name)
		} else {
			sb.WriteString(lbls.String())
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

func formatSelector(sel string) string {
	if !strings.HasPrefix(sel, `{"`) {
		return sel
	}

	es := api.EndpointSelector{}
	err := json.Unmarshal([]byte(sel), &es)
	if err != nil {
		return sel
	}
	selYaml, err := yaml.Marshal(es)
	if err != nil {
		return sel
	}
	return strings.TrimSpace(string(selYaml))
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
