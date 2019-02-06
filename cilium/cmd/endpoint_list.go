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

	"github.com/spf13/cobra"
)

// PolicyEnabled and PolicyDisabled represent the endpoint policy status
const (
	PolicyEnabled  = "Enabled"
	PolicyDisabled = "Disabled"
	UnknownState   = "Unknown"
)

var noHeaders bool

// endpointListCmd represents the endpoint_list command
var endpointListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all endpoints",
	Run: func(cmd *cobra.Command, args []string) {
		listEndpoints()
	},
}

func init() {
	endpointCmd.AddCommand(endpointListCmd)
	endpointListCmd.Flags().BoolVar(&noHeaders, "no-headers", false, "Do not print headers")
	command.AddJSONOutput(endpointListCmd)
}

func endpointPolicyMode(ep *models.Endpoint) (string, string) {
	if ep.Status == nil || ep.Status.Policy == nil || ep.Status.Policy.Realized == nil {
		return UnknownState, UnknownState
	}

	switch ep.Status.Policy.Realized.PolicyEnabled {
	case models.EndpointPolicyEnabledNone:
		return PolicyDisabled, PolicyDisabled
	case models.EndpointPolicyEnabledBoth:
		return PolicyEnabled, PolicyEnabled
	case models.EndpointPolicyEnabledIngress:
		return PolicyEnabled, PolicyDisabled
	case models.EndpointPolicyEnabledEgress:
		return PolicyDisabled, PolicyEnabled
	}

	return UnknownState, UnknownState
}

func endpointAddressPair(ep *models.Endpoint) (string, string) {
	if ep.Status == nil || ep.Status.Networking == nil {
		return UnknownState, UnknownState
	}

	if len(ep.Status.Networking.Addressing) < 1 {
		return "No address", "No address"
	}

	return ep.Status.Networking.Addressing[0].IPV6, ep.Status.Networking.Addressing[0].IPV4
}

func endpointState(ep *models.Endpoint) string {
	if ep.Status == nil {
		return UnknownState
	}

	return string(ep.Status.State)
}

func endpointLabels(ep *models.Endpoint) []string {
	if ep.Status == nil || ep.Status.Labels == nil ||
		len(ep.Status.Labels.SecurityRelevant) == 0 {
		return []string{"no labels"}
	}

	lbls := ep.Status.Labels.SecurityRelevant
	sort.Strings(lbls)
	return lbls
}

func endpointID(ep *models.Endpoint) string {
	id := "<no label id>"
	if ep.Status != nil && ep.Status.Identity != nil {
		id = fmt.Sprintf("%d", ep.Status.Identity.ID)
	}
	return id
}

func listEndpoint(w *tabwriter.Writer, ep *models.Endpoint, id string, label string) {
	policyIngress, policyEgress := endpointPolicyMode(ep)
	ipv6, ipv4 := endpointAddressPair(ep)

	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t\n", ep.ID,
		policyIngress, policyEgress, id, label, ipv6, ipv4, endpointState(ep), ep.Status.Policy.Realized.PolicyRevision)
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
		revisionTitle      = "POLICY REVISION"
	)

	if !noHeaders {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
			endpointTitle, policyIngressTitle, policyEgressTitle, labelsIDTitle, labelsDesTitle, ipv6Title, ipv4Title, statusTitle, revisionTitle)
		fmt.Fprintf(w, "\t%s\t%s\t\t\t\t\t\n", enforcementTitle, enforcementTitle)
	}

	if command.OutputJSON() {
		if err := command.PrintOutput(eps); err != nil {
			os.Exit(1)
		}
		return
	}

	for _, ep := range eps {
		for i, lbl := range endpointLabels(ep) {
			if i == 0 {
				listEndpoint(w, ep, endpointID(ep), lbl)
			} else {
				fmt.Fprintf(w, "\t\t\t\t%s\t\t\t\t\n", lbl)
			}
		}
	}
	w.Flush()
}
