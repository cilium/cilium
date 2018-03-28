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
	"os"
	"sort"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/endpoint"

	"github.com/go-openapi/swag"
	"github.com/spf13/cobra"
)

// PolicyEnabled and PolicyDisabled represent the endpoint policy status
const (
	PolicyEnabled  = "Enabled"
	PolicyDisabled = "Disabled"
)

var noHeaders bool

// endpointListCmd represents the endpoint_list command
var endpointListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all endpoints",
	Run: func(cmd *cobra.Command, args []string) {
		listEndpoints()
	},
}

func init() {
	endpointCmd.AddCommand(endpointListCmd)
	endpointListCmd.Flags().BoolVar(&noHeaders, "no-headers", false, "Do not print headers")
	command.AddJSONOutput(endpointListCmd)
}

func listEndpoint(w *tabwriter.Writer, ep *models.Endpoint, id string, label string) {
	var isIngressPolicyEnabled string
	var isEgressPolicyEnabled string
	switch swag.StringValue(ep.PolicyEnabled) {
	case models.EndpointPolicyEnabledNone:
		isIngressPolicyEnabled = PolicyDisabled
		isEgressPolicyEnabled = PolicyDisabled
	case models.EndpointPolicyEnabledBoth:
		isIngressPolicyEnabled = PolicyEnabled
		isEgressPolicyEnabled = PolicyEnabled
	case models.EndpointPolicyEnabledIngress:
		isIngressPolicyEnabled = PolicyEnabled
		isEgressPolicyEnabled = PolicyDisabled
	case models.EndpointPolicyEnabledEgress:
		isIngressPolicyEnabled = PolicyDisabled
		isEgressPolicyEnabled = PolicyEnabled
	}
	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
		ep.ID, isIngressPolicyEnabled, isEgressPolicyEnabled, id, label, ep.Addressing.IPV6, ep.Addressing.IPV4, ep.State)
}

func listEndpoints() {
	eps, err := client.EndpointList()
	if err != nil {
		Fatalf("cannot get endpoint list: %s\n", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	printEndpointList(w, eps)
}

func printEndpointList(w *tabwriter.Writer, eps []*models.Endpoint) {
	endpoint.OrderEndpointAsc(eps)

	const (
		labelsIDTitle      = "IDENTITY"
		labelsDesTitle     = "LABELS (source:key[=value])"
		ipv6Title          = "IPv6"
		ipv4Title          = "IPv4"
		endpointTitle      = "ENDPOINT"
		statusTitle        = "STATUS"
		policyIngressTitle = "POLICY (ingress)"
		policyEgressTitle  = "POLICY (egress)"
		enforcementTitle   = "ENFORCEMENT"
	)

	if !noHeaders {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			endpointTitle, policyIngressTitle, policyEgressTitle, labelsIDTitle, labelsDesTitle, ipv6Title, ipv4Title, statusTitle)
		fmt.Fprintf(w, "\t%s\t%s\t\t\t\t\t\n", enforcementTitle, enforcementTitle)
	}

	if command.OutputJSON() {
		if err := command.PrintOutput(eps); err != nil {
			os.Exit(1)
		}
		return
	}

	for _, ep := range eps {
		id := "<no label id>"
		if ep.Identity != nil {
			id = fmt.Sprintf("%d", ep.Identity.ID)
		}

		if len(ep.Labels.Status.SecurityRelevant) == 0 {
			listEndpoint(w, ep, id, "no labels")
		} else {

			first := true
			lbls := ep.Labels.Status.SecurityRelevant
			sort.Strings(lbls)
			for _, lbl := range lbls {
				if first {
					listEndpoint(w, ep, id, lbl)
					first = false
				} else {
					fmt.Fprintf(w, "\t\t\t\t%s\t\t\t\t\n", lbl)
				}
			}
		}

	}
	w.Flush()
}
