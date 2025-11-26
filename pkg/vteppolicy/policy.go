// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/types"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// vtepConfig is the gateway configuration derived at runtime from a policy.
type vtepConfig struct {
	// vtepIP is the IP used for vxlan tunnel
	vtepIP netip.Addr
	// vtepMAC is the mac address of remote node behing vxlan tunnel
	vtepMAC mac.MAC
}

// PolicyConfig is the internal representation of CiliumVtepPolicy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	podSelectors []api.EndpointSelector
	dstCIDRs     []netip.Prefix

	matchedEndpoints map[endpointID]*endpointMetadata
	vtepConfig       vtepConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// matchesNodeLabels determines if the given node lables is a match for the
// policy config based on matching labels.
func (config *PolicyConfig) matchesPodLabels(podLabels map[string]string) bool {
	labelsToMatch := k8sLabels.Set(podLabels)
	for _, selector := range config.podSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

// updateMatchedEndpointIDs update the policy's cache of matched endpoint IDs
func (config *PolicyConfig) updateMatchedEndpointIDs(epDataStore map[endpointID]*endpointMetadata) {
	config.matchedEndpoints = make(map[endpointID]*endpointMetadata)
	for _, endpoint := range epDataStore {
		if config.matchesPodLabels(endpoint.labels) {
			config.matchedEndpoints[endpoint.id] = endpoint
		}
	}
}

// forEachEndpointAndCIDR iterates through each combination of endpoints and
// destination/excluded CIDRs of the receiver policy, and for each of them it
// calls the f callback function passing the given endpoint and CIDR, together
// with a boolean value indicating if the CIDR belongs to the excluded ones and
// the vtepConfig of the receiver policy
func (config *PolicyConfig) forEachEndpointAndCIDR(f func(netip.Addr, netip.Prefix, *vtepConfig)) {
	for _, endpoint := range config.matchedEndpoints {
		for _, endpointIP := range endpoint.ips {
			for _, dstCIDR := range config.dstCIDRs {
				f(endpointIP, dstCIDR, &config.vtepConfig)
			}
		}
	}
}

// ParseCVP takes a CiliumVtepPolicy CR and converts to PolicyConfig,
// the internal representation of the vtep policy
func ParseCVP(cvp *v2alpha1.CiliumVtepPolicy) (*PolicyConfig, error) {
	var podSelectorList []api.EndpointSelector
	var dstCidrList []netip.Prefix
	var vtepIP netip.Addr

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := cvp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("must have a name")
	}

	destinationCIDRs := cvp.Spec.DestinationCIDRs
	if destinationCIDRs == nil {
		return nil, fmt.Errorf("destinationCIDRs can't be empty")
	}

	externalVTEP := cvp.Spec.ExternalVTEP
	if externalVTEP == nil {
		return nil, fmt.Errorf("externalVTEP can't be empty")
	}

	vtepIP, err := netip.ParseAddr(externalVTEP.IP)
	if err != nil {
		return nil, fmt.Errorf("cannot parse vtep ip")
	}

	vtepMAC, err := mac.ParseMAC(string(externalVTEP.MAC))
	if err != nil {
		return nil, fmt.Errorf("cannot parse vtep mac %s: %w", vtepMAC, err)
	}

	for _, cidrString := range destinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse destination CIDR %s: %w", cidrString, err)
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, vtepRule := range cvp.Spec.Selectors {
		if vtepRule.NamespaceSelector != nil {
			prefixedNsSelector := vtepRule.NamespaceSelector
			matchLabels := map[string]string{}
			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for k, v := range vtepRule.NamespaceSelector.MatchLabels {
				matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
			}

			prefixedNsSelector.MatchLabels = matchLabels

			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for i, lsr := range vtepRule.NamespaceSelector.MatchExpressions {
				lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
				prefixedNsSelector.MatchExpressions[i] = lsr
			}

			// Empty namespace selector selects all namespaces (i.e., a namespace
			// label exists).
			if len(vtepRule.NamespaceSelector.MatchLabels) == 0 && len(vtepRule.NamespaceSelector.MatchExpressions) == 0 {
				prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
			}
		} else if vtepRule.PodSelector != nil {
			podSelectorList = append(
				podSelectorList,
				api.NewESFromK8sLabelSelector("", vtepRule.PodSelector))
		} else {
			return nil, fmt.Errorf("cannot have both nil namespace selector and nil pod selector")
		}
	}

	return &PolicyConfig{
		podSelectors: podSelectorList,
		dstCIDRs:     dstCidrList,
		vtepConfig: vtepConfig{
			vtepIP:  vtepIP,
			vtepMAC: vtepMAC,
		},
		matchedEndpoints: make(map[endpointID]*endpointMetadata),
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseCEGPConfigID takes a CiliumVtepPolicy CR and returns only the config id
func ParseCVPConfigID(cvp *v2alpha1.CiliumVtepPolicy) types.NamespacedName {
	return policyID{
		Name: cvp.Name,
	}
}
