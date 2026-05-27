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
var topPolicySelectorsByIdentities bool
var topPolicySelectorsLimit int
var topPolicySelectorsIdentityThreshold int

type policySelectorIdentityCount struct {
	IdentityCount int    `json:"identity_count"`
	Policy        string `json:"policy"`
	Namespace     string `json:"namespace"`
	DerivedFrom   string `json:"derived_from"`
	UID           string `json:"uid"`
}

// policyCacheGetCmd represents the policy selectors commands
var policyCacheGetCmd = func(name, description string, f func() (models.SelectorCache, error)) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: description,
		Run: func(cmd *cobra.Command, args []string) {
			if resp, err := f(); err != nil {
				Fatalf("Cannot get policy: %s\n", err)
			} else if topPolicySelectorsByIdentities {
				if topPolicySelectorsLimit < 0 {
					Fatalf("--limit must be greater than or equal to 0\n")
				}
				if topPolicySelectorsIdentityThreshold < 0 {
					Fatalf("--identity-threshold must be greater than or equal to 0\n")
				}

				policies := getTopPolicySelectorIdentityCounts(
					resp,
					topPolicySelectorsIdentityThreshold,
					topPolicySelectorsLimit,
				)
				if command.OutputOption() {
					if err := command.PrintOutput(policies); err != nil {
						os.Exit(1)
					}
				} else {
					printPolicySelectorIdentityCounts(policies)
				}
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

func getTopPolicySelectorIdentityCounts(resp models.SelectorCache, identityThreshold, limit int) []policySelectorIdentityCount {
	countsByPolicy := map[policySelectorIdentityCount]policySelectorIdentityCount{}

	for _, mapping := range resp {
		if mapping == nil {
			continue
		}

		identityCount := len(mapping.Identities)
		if identityCount < identityThreshold {
			continue
		}

		lblsList := constructLabelArrayListFromAPIType(mapping.Labels)
		if len(lblsList) == 0 {
			upsertPolicySelectorIdentityCount(countsByPolicy, policySelectorIdentityCount{IdentityCount: identityCount})
			continue
		}

		for _, lbls := range lblsList {
			policy := policySelectorIdentityCountFromLabels(lbls, identityCount)
			upsertPolicySelectorIdentityCount(countsByPolicy, policy)
		}
	}

	policies := make([]policySelectorIdentityCount, 0, len(countsByPolicy))
	for _, policy := range countsByPolicy {
		policies = append(policies, policy)
	}

	sort.Slice(policies, func(i, j int) bool {
		if policies[i].IdentityCount != policies[j].IdentityCount {
			return policies[i].IdentityCount > policies[j].IdentityCount
		}
		if policies[i].Namespace != policies[j].Namespace {
			return policies[i].Namespace < policies[j].Namespace
		}
		if policies[i].Policy != policies[j].Policy {
			return policies[i].Policy < policies[j].Policy
		}
		if policies[i].DerivedFrom != policies[j].DerivedFrom {
			return policies[i].DerivedFrom < policies[j].DerivedFrom
		}
		return policies[i].UID < policies[j].UID
	})

	if limit > 0 && len(policies) > limit {
		return policies[:limit]
	}

	return policies
}

func policySelectorIdentityCountFromLabels(lbls labels.LabelArray, identityCount int) policySelectorIdentityCount {
	policy := policySelectorIdentityCount{
		IdentityCount: identityCount,
		Policy:        lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sconst.PolicyLabelName),
		Namespace:     lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sconst.PolicyLabelNamespace),
		DerivedFrom:   lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sconst.PolicyLabelDerivedFrom),
		UID:           lbls.Get(labels.LabelSourceK8sKeyPrefix + k8sconst.PolicyLabelUID),
	}

	if policy.Policy == "" && policy.Namespace == "" && policy.DerivedFrom == "" && policy.UID == "" {
		return policySelectorIdentityCount{IdentityCount: identityCount}
	}

	return policy
}

func upsertPolicySelectorIdentityCount(countsByPolicy map[policySelectorIdentityCount]policySelectorIdentityCount, policy policySelectorIdentityCount) {
	key := policy
	key.IdentityCount = 0

	existing, ok := countsByPolicy[key]
	if !ok || policy.IdentityCount > existing.IdentityCount {
		countsByPolicy[key] = policy
	}
}

func printPolicySelectorIdentityCounts(policies []policySelectorIdentityCount) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "IDENTITY COUNT\tPOLICY\tNAMESPACE\tDERIVED FROM\tUID\n")
	for _, policy := range policies {
		policyName := policy.Policy
		if policyName == "" {
			policyName = "<unknown>"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", policy.IdentityCount, policyName, policy.Namespace, policy.DerivedFrom, policy.UID)
	}
	w.Flush()
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
		name          string
		description   string
		topIdentities bool
		f             func() (models.SelectorCache, error)
	}{
		{
			name:          "selectors",
			description:   "Display cached information about selectors",
			topIdentities: true,
			f:             func() (models.SelectorCache, error) { return client.PolicyCacheGet() },
		},
		{
			name:        "subject-selectors",
			description: "Display cached information about subject selectors",
			f:           func() (models.SelectorCache, error) { return client.SubjectPolicySelectorsGet() },
		},
	} {
		cmd := policyCacheGetCmd(c.name, c.description, c.f)
		cmd.Flags().BoolVarP(&verbosePolicySelectors, "verbose", "v", false, "Show the full labels")
		if c.topIdentities {
			cmd.Flags().BoolVar(&topPolicySelectorsByIdentities, "top-identities", false, "Show policies with the highest selector identity count")
			cmd.Flags().IntVar(&topPolicySelectorsLimit, "limit", 20, "Limit number of policies shown with --top-identities (0 for all)")
			cmd.Flags().IntVar(&topPolicySelectorsIdentityThreshold, "identity-threshold", 0, "Minimum selector identity count shown with --top-identities")
		}
		PolicyCmd.AddCommand(cmd)
		command.AddOutputOption(cmd)
	}
}
