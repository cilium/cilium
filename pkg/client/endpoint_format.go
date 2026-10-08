// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"slices"
	"sort"
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
)

const (
	policyEnabled  = "Enabled"
	policyDisabled = "Disabled"
	policyAudit    = "Disabled (Audit)"
	unknownState   = "Unknown"
)

// FormatEndpoints writes eps as the endpoint list table, sorted by ID. It
// sorts eps in place, which cilium debuginfo relies on to keep its
// per-endpoint sections in the same order.
func FormatEndpoints(w *tabwriter.Writer, eps []*models.Endpoint, noHeaders bool) {
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

func listEndpoint(w *tabwriter.Writer, ep *models.Endpoint, id string, label string) {
	policyIngress, policyEgress := endpointPolicyMode(ep)
	ipv6, ipv4 := endpointAddressPair(ep)

	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n", ep.ID,
		policyIngress, policyEgress, id, label, ipv6, ipv4, endpointState(ep))
}

func endpointPolicyMode(ep *models.Endpoint) (string, string) {
	if ep.Status == nil || ep.Status.Policy == nil || ep.Status.Policy.Realized == nil {
		return unknownState, unknownState
	}

	switch ep.Status.Policy.Realized.PolicyEnabled {
	case models.EndpointPolicyEnabledNone:
		return policyDisabled, policyDisabled
	case models.EndpointPolicyEnabledBoth:
		return policyEnabled, policyEnabled
	case models.EndpointPolicyEnabledIngress:
		return policyEnabled, policyDisabled
	case models.EndpointPolicyEnabledEgress:
		return policyDisabled, policyEnabled
	case models.EndpointPolicyEnabledAuditDashBoth:
		return policyAudit, policyAudit
	case models.EndpointPolicyEnabledAuditDashIngress:
		return policyAudit, policyDisabled
	case models.EndpointPolicyEnabledAuditDashEgress:
		return policyDisabled, policyAudit
	}

	return unknownState, unknownState
}

func endpointAddressPair(ep *models.Endpoint) (string, string) {
	if ep.Status == nil || ep.Status.Networking == nil {
		return unknownState, unknownState
	}

	if len(ep.Status.Networking.Addressing) < 1 {
		return "No address", "No address"
	}

	return ep.Status.Networking.Addressing[0].IPv6, ep.Status.Networking.Addressing[0].IPv4
}

func endpointState(ep *models.Endpoint) string {
	if ep.Status == nil || ep.Status.State == nil {
		return unknownState
	}

	return string(*ep.Status.State)
}

func endpointLabels(ep *models.Endpoint) []string {
	if ep.Status == nil || ep.Status.Labels == nil ||
		len(ep.Status.Labels.SecurityRelevant) == 0 {
		return []string{"no labels"}
	}

	lbls := ep.Status.Labels.SecurityRelevant
	slices.Sort(lbls)
	return lbls
}

func endpointID(ep *models.Endpoint) string {
	id := "<no label id>"
	if ep.Status != nil && ep.Status.Identity != nil {
		id = fmt.Sprintf("%d", ep.Status.Identity.ID)
	}
	return id
}
