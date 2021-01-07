// Copyright 2020 Authors of Cilium
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

	"github.com/cilium/cilium-cli/internal/cli/policy"

	"github.com/spf13/cobra"
)

func newCmdPolicy() *cobra.Command {
	var (
		namespace       string
		noPodsSelected  bool
		containsL4      bool
		containsIngress bool
		containsEgress  bool
		selects         string
	)

	root := &cobra.Command{
		Use:   "policy",
		Short: "Network policy management",
	}

	policyList := &cobra.Command{
		Use:   "list",
		Short: "List network policies",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			policies, err := policy.ListPolicies(k8sClient, policy.ListPoliciesParams{
				Namespace: namespace,
				Selects:   selects,
			})

			if err != nil {
				return err
			}

			for name, p := range policies.PolicyMap {
				if noPodsSelected && p.SelectedPods > 0 {
					continue
				}

				if containsL4 && !p.ContainsL4 {
					continue
				}

				if containsIngress && p.NumberIngress == 0 {
					continue
				}

				if containsEgress && p.NumberEgress == 0 {
					continue
				}

				fmt.Printf("%s: selected-pods: %d, ingress: %d, egress: %d, specs: %d\n",
					name, p.SelectedPods, p.NumberIngress, p.NumberEgress, p.NumberSpecs)
			}

			return nil
		},
	}
	policyList.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace to list policies in")
	policyList.Flags().BoolVar(&noPodsSelected, "no-pods-selected", false, "Only list policies that don't select any pods")
	policyList.Flags().BoolVar(&containsL4, "contains-l4", false, "Show policies that contain L4 policy filtering")
	policyList.Flags().BoolVar(&containsIngress, "contains-ingress", false, "Show policies that contain ingress policy filtering")
	policyList.Flags().BoolVar(&containsEgress, "contains-egress", false, "Show policies that contain egress policy filtering")
	policyList.Flags().StringVar(&selects, "selects", "", "Selects a pod with the specified label")
	policyList.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	root.AddCommand(policyList)

	return root
}
