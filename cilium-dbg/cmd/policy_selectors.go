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
var topPolicySelectorsByEndpoints bool
var showPolicySelectorDirection bool
var topPolicySelectorsLimit int
var topPolicySelectorsIdentityThreshold int

type policySelectorIdentityCount struct {
	IdentityCount int    `json:"identity_count"`
	Direction     string `json:"direction,omitempty"`
	Policy        string `json:"policy"`
	Namespace     string `json:"namespace"`
	DerivedFrom   string `json:"derived_from"`
	UID           string `json:"uid"`
}

type policySelectorEndpointIdentityCount struct {
	IdentityCount        int      `json:"identity_count"`
	IngressIdentityCount *int     `json:"ingress_identity_count,omitempty"`
	EgressIdentityCount  *int     `json:"egress_identity_count,omitempty"`
	EndpointID           int64    `json:"endpoint_id"`
	EndpointIdentity     int64    `json:"endpoint_identity"`
	IPv6                 string   `json:"ipv6"`
	IPv4                 string   `json:"ipv4"`
	Labels               []string `json:"labels"`
}

type policySelectorOrigin struct {
	Direction string
	Policy    policySelectorIdentityCount
}

const (
	selectorDirectionEgress  = "egress"
	selectorDirectionIngress = "ingress"
)

// policyCacheGetCmd represents the policy selectors commands
var policyCacheGetCmd = func(name, description string, f func() (models.SelectorCache, error)) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: description,
		Run: func(cmd *cobra.Command, args []string) {
			if resp, err := f(); err != nil {
				Fatalf("Cannot get policy: %s\n", err)
			} else if topPolicySelectorsByIdentities || topPolicySelectorsByEndpoints {
				validateTopPolicySelectorsOptions()
				if topPolicySelectorsByEndpoints {
					subjectSelectors, err := client.SubjectPolicySelectorsGet()
					if err != nil {
						Fatalf("Cannot get subject policy selectors: %s\n", err)
					}
					endpoints, err := client.EndpointList()
					if err != nil {
						Fatalf("Cannot get endpoint list: %s\n", err)
					}
					endpointCounts := getTopPolicySelectorEndpointIdentityCounts(
						resp,
						subjectSelectors,
						endpoints,
						topPolicySelectorsIdentityThreshold,
						topPolicySelectorsLimit,
						showPolicySelectorDirection,
					)
					if command.OutputOption() {
						if err := command.PrintOutput(endpointCounts); err != nil {
							os.Exit(1)
						}
					} else {
						printPolicySelectorEndpointIdentityCounts(endpointCounts, showPolicySelectorDirection)
					}
					return
				}
				policies := getTopPolicySelectorIdentityCounts(
					resp,
					topPolicySelectorsIdentityThreshold,
					topPolicySelectorsLimit,
					showPolicySelectorDirection,
				)
				if command.OutputOption() {
					if err := command.PrintOutput(policies); err != nil {
						os.Exit(1)
					}
				} else {
					printPolicySelectorIdentityCounts(policies, showPolicySelectorDirection)
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

func validateTopPolicySelectorsOptions() {
	if topPolicySelectorsByIdentities && topPolicySelectorsByEndpoints {
		Fatalf("--top-identities and --top-endpoints cannot be used together\n")
	}
	if topPolicySelectorsLimit < 0 {
		Fatalf("--limit must be greater than or equal to 0\n")
	}
	if topPolicySelectorsIdentityThreshold < 0 {
		Fatalf("--identity-threshold must be greater than or equal to 0\n")
	}
}

func getTopPolicySelectorIdentityCounts(resp models.SelectorCache, identityThreshold, limit int, showDirection bool) []policySelectorIdentityCount {
	selectedIdentitiesByPolicyAndDirection := getPolicySelectorIdentitiesByPolicyAndDirection(resp)
	countsByPolicy := map[policySelectorIdentityCount]int{}

	for policy, identities := range selectedIdentitiesByPolicyAndDirection {
		identityCount := len(identities)
		if showDirection {
			countsByPolicy[policy] = identityCount
			continue
		}

		policy.Direction = ""
		countsByPolicy[policy] += identityCount
	}

	policies := make([]policySelectorIdentityCount, 0, len(countsByPolicy))
	for policy, identityCount := range countsByPolicy {
		if identityCount < identityThreshold {
			continue
		}
		policy.IdentityCount = identityCount
		policies = append(policies, policy)
	}

	sortPolicySelectorIdentityCounts(policies)

	if limit > 0 && len(policies) > limit {
		return policies[:limit]
	}

	return policies
}

func getTopPolicySelectorEndpointIdentityCounts(policySelectors, subjectSelectors models.SelectorCache, endpoints []*models.Endpoint, identityThreshold, limit int, showDirection bool) []policySelectorEndpointIdentityCount {
	selectedIdentitiesByPolicy := getPolicySelectorIdentitiesByPolicyAndDirection(policySelectors)
	endpointsByIdentity := getEndpointsByIdentity(endpoints)

	selectedIdentitiesByEndpoint := map[int64]map[string]map[int64]struct{}{}
	endpointsByID := map[int64]*models.Endpoint{}
	for _, subjectSelector := range subjectSelectors {
		if subjectSelector == nil {
			continue
		}

		for _, origin := range policySelectorOrigins(subjectSelector) {
			policy := policySelectorIdentityCountKey(origin.Policy)
			selectedIdentities, ok := selectedIdentitiesByPolicy[policy]
			if !ok {
				continue
			}

			for _, identity := range subjectSelector.Identities {
				for _, endpoint := range endpointsByIdentity[identity] {
					endpointsByID[endpoint.ID] = endpoint
					selectedIdentitiesByDirection, ok := selectedIdentitiesByEndpoint[endpoint.ID]
					if !ok {
						selectedIdentitiesByDirection = map[string]map[int64]struct{}{}
						selectedIdentitiesByEndpoint[endpoint.ID] = selectedIdentitiesByDirection
					}
					endpointIdentities, ok := selectedIdentitiesByDirection[origin.Direction]
					if !ok {
						endpointIdentities = map[int64]struct{}{}
						selectedIdentitiesByDirection[origin.Direction] = endpointIdentities
					}

					for selectedIdentity := range selectedIdentities {
						endpointIdentities[selectedIdentity] = struct{}{}
					}
				}
			}
		}
	}

	endpointCounts := make([]policySelectorEndpointIdentityCount, 0, len(selectedIdentitiesByEndpoint))
	for endpointID, identitiesByDirection := range selectedIdentitiesByEndpoint {
		identityCount := 0
		for _, identities := range identitiesByDirection {
			identityCount += len(identities)
		}
		if identityCount < identityThreshold {
			continue
		}

		endpoint := endpointsByID[endpointID]
		ipv6, ipv4 := endpointAddressPair(endpoint)
		endpointCount := policySelectorEndpointIdentityCount{
			IdentityCount:    identityCount,
			EndpointID:       endpointID,
			EndpointIdentity: endpoint.Status.Identity.ID,
			IPv6:             ipv6,
			IPv4:             ipv4,
			Labels:           policySelectorEndpointLabels(endpoint),
		}
		if showDirection {
			ingressIdentityCount := len(identitiesByDirection[selectorDirectionIngress])
			egressIdentityCount := len(identitiesByDirection[selectorDirectionEgress])
			endpointCount.IngressIdentityCount = &ingressIdentityCount
			endpointCount.EgressIdentityCount = &egressIdentityCount
		}
		endpointCounts = append(endpointCounts, endpointCount)
	}

	sortPolicySelectorEndpointIdentityCounts(endpointCounts)

	if limit > 0 && len(endpointCounts) > limit {
		return endpointCounts[:limit]
	}

	return endpointCounts
}

func getPolicySelectorIdentitiesByPolicyAndDirection(resp models.SelectorCache) map[policySelectorIdentityCount]map[int64]struct{} {
	selectedIdentitiesByPolicy := map[policySelectorIdentityCount]map[int64]struct{}{}
	for _, mapping := range resp {
		if mapping == nil {
			continue
		}

		for _, origin := range policySelectorOrigins(mapping) {
			policy := policySelectorIdentityCountKey(origin.Policy)
			identities, ok := selectedIdentitiesByPolicy[policy]
			if !ok {
				identities = map[int64]struct{}{}
				selectedIdentitiesByPolicy[policy] = identities
			}

			for _, identity := range mapping.Identities {
				identities[identity] = struct{}{}
			}
		}
	}
	return selectedIdentitiesByPolicy
}

func policySelectorOrigins(mapping *models.SelectorIdentityMapping) []policySelectorOrigin {
	if len(mapping.Origins) > 0 {
		origins := make([]policySelectorOrigin, 0, len(mapping.Origins))
		for _, origin := range mapping.Origins {
			if origin == nil {
				continue
			}
			policy := policySelectorIdentityCountFromLabels(constructLabelArrayFromAPIType(origin.Labels), 0)
			policy.Direction = origin.Direction
			origins = append(origins, policySelectorOrigin{
				Direction: origin.Direction,
				Policy:    policy,
			})
		}
		return origins
	}

	lblsList := constructLabelArrayListFromAPIType(mapping.Labels)
	if len(lblsList) == 0 {
		return []policySelectorOrigin{{}}
	}

	origins := make([]policySelectorOrigin, 0, len(lblsList))
	for _, lbls := range lblsList {
		origins = append(origins, policySelectorOrigin{
			Policy: policySelectorIdentityCountFromLabels(lbls, 0),
		})
	}
	return origins
}

func sortPolicySelectorIdentityCounts(policies []policySelectorIdentityCount) {
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
		if policies[i].Direction != policies[j].Direction {
			return policies[i].Direction < policies[j].Direction
		}
		if policies[i].DerivedFrom != policies[j].DerivedFrom {
			return policies[i].DerivedFrom < policies[j].DerivedFrom
		}
		return policies[i].UID < policies[j].UID
	})
}

func sortPolicySelectorEndpointIdentityCounts(endpointCounts []policySelectorEndpointIdentityCount) {
	sort.Slice(endpointCounts, func(i, j int) bool {
		if endpointCounts[i].IdentityCount != endpointCounts[j].IdentityCount {
			return endpointCounts[i].IdentityCount > endpointCounts[j].IdentityCount
		}
		if endpointCounts[i].EndpointID != endpointCounts[j].EndpointID {
			return endpointCounts[i].EndpointID < endpointCounts[j].EndpointID
		}
		if endpointCounts[i].EndpointIdentity != endpointCounts[j].EndpointIdentity {
			return endpointCounts[i].EndpointIdentity < endpointCounts[j].EndpointIdentity
		}
		if endpointCounts[i].IPv6 != endpointCounts[j].IPv6 {
			return endpointCounts[i].IPv6 < endpointCounts[j].IPv6
		}
		return endpointCounts[i].IPv4 < endpointCounts[j].IPv4
	})
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

func policySelectorIdentityCountKey(policy policySelectorIdentityCount) policySelectorIdentityCount {
	policy.IdentityCount = 0
	return policy
}

func getEndpointsByIdentity(endpoints []*models.Endpoint) map[int64][]*models.Endpoint {
	endpointsByIdentity := map[int64][]*models.Endpoint{}
	for _, endpoint := range endpoints {
		if endpoint == nil || endpoint.Status == nil || endpoint.Status.Identity == nil {
			continue
		}

		identity := endpoint.Status.Identity.ID
		endpointsByIdentity[identity] = append(endpointsByIdentity[identity], endpoint)
	}
	return endpointsByIdentity
}

func policySelectorEndpointLabels(endpoint *models.Endpoint) []string {
	if endpoint == nil || endpoint.Status == nil || endpoint.Status.Labels == nil ||
		len(endpoint.Status.Labels.SecurityRelevant) == 0 {
		return []string{}
	}

	lbls := append([]string(nil), endpoint.Status.Labels.SecurityRelevant...)
	sort.Strings(lbls)
	return lbls
}

func printPolicySelectorIdentityCounts(policies []policySelectorIdentityCount, showDirection bool) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	if showDirection {
		fmt.Fprintf(w, "IDENTITY COUNT\tDIRECTION\tPOLICY\tNAMESPACE\tDERIVED FROM\tUID\n")
	} else {
		fmt.Fprintf(w, "IDENTITY COUNT\tPOLICY\tNAMESPACE\tDERIVED FROM\tUID\n")
	}
	for _, policy := range policies {
		policyName := policy.Policy
		if policyName == "" {
			policyName = "<unknown>"
		}
		if showDirection {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", policy.IdentityCount, policy.Direction, policyName, policy.Namespace, policy.DerivedFrom, policy.UID)
		} else {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", policy.IdentityCount, policyName, policy.Namespace, policy.DerivedFrom, policy.UID)
		}
	}
	w.Flush()
}

func printPolicySelectorEndpointIdentityCounts(endpoints []policySelectorEndpointIdentityCount, showDirection bool) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	if showDirection {
		fmt.Fprintf(w, "IDENTITY COUNT\tINGRESS IDENTITY COUNT\tEGRESS IDENTITY COUNT\tENDPOINT\tIDENTITY\tIPv6\tIPv4\tLABELS\n")
	} else {
		fmt.Fprintf(w, "IDENTITY COUNT\tENDPOINT\tIDENTITY\tIPv6\tIPv4\tLABELS\n")
	}
	for _, endpoint := range endpoints {
		labels := strings.Join(endpoint.Labels, ",")
		if labels == "" {
			labels = "no labels"
		}
		if showDirection {
			fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n",
				endpoint.IdentityCount,
				identityCountValue(endpoint.IngressIdentityCount),
				identityCountValue(endpoint.EgressIdentityCount),
				endpoint.EndpointID,
				endpoint.EndpointIdentity,
				endpoint.IPv6,
				endpoint.IPv4,
				labels,
			)
		} else {
			fmt.Fprintf(w, "%d\t%d\t%d\t%s\t%s\t%s\n",
				endpoint.IdentityCount,
				endpoint.EndpointID,
				endpoint.EndpointIdentity,
				endpoint.IPv6,
				endpoint.IPv4,
				labels,
			)
		}
	}
	w.Flush()
}

func identityCountValue(count *int) int {
	if count == nil {
		return 0
	}
	return *count
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
		list = append(list, constructLabelArrayFromAPIType(la))
	}
	return list
}

func constructLabelArrayFromAPIType(in models.LabelArray) labels.LabelArray {
	lbls := make(labels.LabelArray, 0, len(in))
	for _, l := range in {
		lbls = append(lbls, labels.Label{
			Key:    l.Key,
			Value:  l.Value,
			Source: l.Source,
		})
	}
	return lbls
}

func init() {
	for _, c := range []struct {
		name        string
		description string
		topCounts   bool
		f           func() (models.SelectorCache, error)
	}{
		{
			name:        "selectors",
			description: "Display cached information about selectors",
			topCounts:   true,
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
		if c.topCounts {
			cmd.Flags().BoolVar(&topPolicySelectorsByIdentities, "top-identities", false, "Show policies with the highest selector identity count")
			cmd.Flags().BoolVar(&topPolicySelectorsByEndpoints, "top-endpoints", false, "Show endpoints with the highest selected identity count")
			cmd.Flags().BoolVar(&showPolicySelectorDirection, "show-direction", false, "Show ingress and egress identity counts separately")
			cmd.Flags().IntVar(&topPolicySelectorsLimit, "limit", 20, "Limit number of rows shown with --top-identities or --top-endpoints (0 for all)")
			cmd.Flags().IntVar(&topPolicySelectorsIdentityThreshold, "identity-threshold", 0, "Minimum identity count shown with --top-identities or --top-endpoints")
		}
		PolicyCmd.AddCommand(cmd)
		command.AddOutputOption(cmd)
	}
}
