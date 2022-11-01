// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

// PolicyEnabled and PolicyDisabled represent the endpoint policy status
const (
	PolicyEnabled  = "Enabled"
	PolicyDisabled = "Disabled"
	PolicyAudit    = "Disabled (Audit)"
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
	command.AddOutputOption(endpointListCmd)
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
	case models.EndpointPolicyEnabledAuditDashBoth:
		return PolicyAudit, PolicyAudit
	case models.EndpointPolicyEnabledAuditDashIngress:
		return PolicyAudit, PolicyDisabled
	case models.EndpointPolicyEnabledAuditDashEgress:
		return PolicyDisabled, PolicyAudit
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
	if ep.Status == nil || ep.Status.State == nil {
		return UnknownState
	}

	return string(*ep.Status.State)
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

	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n", ep.ID,
		policyIngress, policyEgress, id, label, ipv6, ipv4, endpointState(ep))
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
	sort.Slice(eps, func(i, j int) bool { return eps[i].ID < eps[j].ID })

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

	if command.OutputOption() {
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
