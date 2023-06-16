// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
	"go4.org/netipx"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/ip"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// policyGatewayConfig is the internal representation of an egress gateway,
// describing which node should act as egress gateway for a given policy.
type policyGatewayConfig struct {
	nodeSelector api.EndpointSelector
	iface        string
	egressIP     netip.Addr
}

// gatewayConfig is the gateway configuration derived at runtime from a policy.
//
// Some of these fields are derived from the running system as the policy may
// specify only the egress IP (and so we need to figure out which interface has
// that IP assigned to) or the interface (and in this case we need to find the
// first IPv4 assigned to that).
type gatewayConfig struct {
	// ifaceName is the name of the interface used to SNAT traffic
	ifaceName string
	// ifaceIndex is the index of the interface used to SNAT traffic
	ifaceIndex int
	// egressIP is the IP used to SNAT traffic
	egressIP netip.Prefix
	// gatewayIP is the node internal IP of the gateway
	gatewayIP netip.Addr

	// localNodeConfiguredAsGateway tells if the local node is configured to
	// act as an egress gateway node for this config.
	// This information is used to decide if it is necessary to install ENI
	// IP rules/routes
	localNodeConfiguredAsGateway bool
}

// PolicyConfig is the internal representation of CiliumEgressGatewayPolicy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []netip.Prefix
	excludedCIDRs     []netip.Prefix

	policyGwConfig *policyGatewayConfig

	matchedEndpoints map[endpointID]*endpointMetadata
	gatewayConfig    gatewayConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// matchesEndpointLabels determines if the given endpoint is a match for the
// policy config based on matching labels.
func (config *PolicyConfig) matchesEndpointLabels(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
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
		if config.matchesEndpointLabels(endpoint) {
			config.matchedEndpoints[endpoint.id] = endpoint
		}
	}
}

func (config *policyGatewayConfig) selectsNodeAsGateway(node nodeTypes.Node) bool {
	return config.nodeSelector.Matches(k8sLabels.Set(node.Labels))
}

func (config *PolicyConfig) regenerateGatewayConfig(manager *Manager) {
	gwc := gatewayConfig{
		egressIP:  netip.PrefixFrom(GatewayNotFoundIPv4, 0),
		gatewayIP: GatewayNotFoundIPv4,
	}

	policyGwc := config.policyGwConfig

	for _, node := range manager.nodes {
		if !policyGwc.selectsNodeAsGateway(node) {
			continue
		}

		gwc.gatewayIP, _ = ip.AddrFromIP(node.GetK8sNodeIP())

		if node.IsLocal() {
			err := gwc.deriveFromPolicyGatewayConfig(policyGwc)
			if err != nil {
				logger := log.WithFields(logrus.Fields{
					logfields.CiliumEgressGatewayPolicyName: config.id,
					logfields.Interface:                     policyGwc.iface,
					logfields.EgressIP:                      policyGwc.egressIP,
				})

				logger.WithError(err).Error("Failed to derive policy gateway configuration")
			}
		}

		break
	}

	config.gatewayConfig = gwc
}

// deriveFromPolicyGatewayConfig retrieves all the missing gateway configuration
// data (such as egress IP or interface) given a policy egress gateway config
func (gwc *gatewayConfig) deriveFromPolicyGatewayConfig(gc *policyGatewayConfig) error {
	var err error

	gwc.localNodeConfiguredAsGateway = false

	switch {
	case gc.iface != "":
		// If the gateway config specifies an interface, use the first IPv4 assigned to that
		// interface as egress IP
		gwc.egressIP, gwc.ifaceIndex, err = getIfaceFirstIPv4Address(gc.iface)
		if err != nil {
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	case gc.egressIP != GatewayNotFoundIPv4:
		// If the gateway config specifies an egress IP, use the interface with that IP as egress
		// interface
		gwc.ifaceName, gwc.ifaceIndex, gwc.egressIP, err = getIfaceWithIPv4Address(gc.egressIP)
		if err != nil {
			return fmt.Errorf("failed to retrieve interface with egress IP: %w", err)
		}
	default:
		// If the gateway config doesn't specify any egress IP or interface, use the
		// interface with the IPv4 default route
		iface, err := route.NodeDeviceWithDefaultRoute(true, false)
		if err != nil {
			return fmt.Errorf("failed to find interface with default route: %w", err)
		}

		gwc.ifaceName = iface.Attrs().Name
		gwc.egressIP, gwc.ifaceIndex, err = getIfaceFirstIPv4Address(gwc.ifaceName)
		if err != nil {
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	}

	gwc.localNodeConfiguredAsGateway = true

	return nil
}

// destinationMinusExcludedCIDRs will return, for a given policy, a list of all
// destination CIDRs to which the excluded CIDRs have been subtracted.
func (config *PolicyConfig) destinationMinusExcludedCIDRs() []netip.Prefix {
	if len(config.excludedCIDRs) == 0 {
		return config.dstCIDRs
	}

	cidrs := []netip.Prefix{}

	for _, dstCIDR := range config.dstCIDRs {
		dstCIDRMinusExcludedCIDRs := []netip.Prefix{dstCIDR}
		for _, excludedCIDR := range config.excludedCIDRs {
			newDstCIDRMinuxExcludedCIDRs := []netip.Prefix{}
			for _, cidr := range dstCIDRMinusExcludedCIDRs {
				leftNets, _, rightNets := ip.PartitionCIDR(*netipx.PrefixIPNet(cidr), *netipx.PrefixIPNet(excludedCIDR))
				var rightPrefixes, leftPrefixes []netip.Prefix
				for i := range leftNets {
					r := leftNets[i]
					if p, ok := netipx.FromStdIPNet(r); ok {
						rightPrefixes = append(rightPrefixes, p)
					}
				}
				newDstCIDRMinuxExcludedCIDRs = append(newDstCIDRMinuxExcludedCIDRs, rightPrefixes...)
				for i := range rightNets {
					l := rightNets[i]
					if p, ok := netipx.FromStdIPNet(l); ok {
						leftPrefixes = append(leftPrefixes, p)
					}
				}
				newDstCIDRMinuxExcludedCIDRs = append(newDstCIDRMinuxExcludedCIDRs, leftPrefixes...)
			}

			dstCIDRMinusExcludedCIDRs = newDstCIDRMinuxExcludedCIDRs
		}

		cidrs = append(cidrs, dstCIDRMinusExcludedCIDRs...)
	}

	return cidrs
}

// forEachEndpointAndCIDR iterates through each combination of endpoints and
// destination/excluded CIDRs of the receiver policy, and for each of them it
// calls the f callback function passing the given endpoint and CIDR, together
// with a boolean value indicating if the CIDR belongs to the excluded ones and
// the gatewayConfig of the receiver policy
func (config *PolicyConfig) forEachEndpointAndCIDR(f func(netip.Addr, netip.Prefix, bool, *gatewayConfig)) {

	for _, endpoint := range config.matchedEndpoints {
		for _, endpointIP := range endpoint.ips {
			isExcludedCIDR := false
			for _, dstCIDR := range config.dstCIDRs {
				f(endpointIP, dstCIDR, isExcludedCIDR, &config.gatewayConfig)
			}

			isExcludedCIDR = true
			for _, excludedCIDR := range config.excludedCIDRs {
				f(endpointIP, excludedCIDR, isExcludedCIDR, &config.gatewayConfig)
			}
		}
	}
}

// forEachEndpointAndDestination iterates through each combination of endpoints
// and computed destination (i.e. the effective destination CIDR space, defined
// as the diff between the destination and the excluded CIDRs) of the receiver
// policy, and for each of them it calls the f callback function, passing the
// given endpoint and CIDR, together with the gatewayConfig of the receiver
// policy
func (config *PolicyConfig) forEachEndpointAndDestination(f func(netip.Addr, netip.Prefix, *gatewayConfig)) {

	cidrs := config.destinationMinusExcludedCIDRs()

	for _, endpoint := range config.matchedEndpoints {
		for _, endpointIP := range endpoint.ips {
			for _, cidr := range cidrs {
				f(endpointIP, cidr, &config.gatewayConfig)
			}
		}
	}
}

// ParseCEGP takes a CiliumEgressGatewayPolicy CR and converts to PolicyConfig,
// the internal representation of the egress gateway policy
func ParseCEGP(cegp *v2.CiliumEgressGatewayPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []netip.Prefix
	var excludedCIDRs []netip.Prefix

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := cegp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("CiliumEgressGatewayPolicy must have a name")
	}

	egressGateway := cegp.Spec.EgressGateway
	if egressGateway.Interface != "" && egressGateway.EgressIP != "" {
		return nil, fmt.Errorf("CiliumEgressGatewayPolicy's gateway configuration can't specify both an interface and an egress IP")
	}

	egressIP, err := netip.ParseAddr(egressGateway.EgressIP)
	if err != nil {
		return nil, fmt.Errorf("failed to parse agress gateway IP %s", egressGateway.EgressIP)
	}

	policyGwc := &policyGatewayConfig{
		nodeSelector: api.NewESFromK8sLabelSelector("", egressGateway.NodeSelector),
		iface:        egressGateway.Interface,
		egressIP:     egressIP,
	}

	for _, cidrString := range cegp.Spec.DestinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumEgressGatewayPolicyName: name}).Warn("Error parsing cidr.")
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, cidrString := range cegp.Spec.ExcludedCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumEgressGatewayPolicyName: name}).Warn("Error parsing cidr.")
			return nil, err
		}
		excludedCIDRs = append(excludedCIDRs, cidr)
	}

	for _, egressRule := range cegp.Spec.Selectors {
		if egressRule.NamespaceSelector != nil {
			prefixedNsSelector := egressRule.NamespaceSelector
			matchLabels := map[string]string{}
			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for k, v := range egressRule.NamespaceSelector.MatchLabels {
				matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
			}

			prefixedNsSelector.MatchLabels = matchLabels

			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for i, lsr := range egressRule.NamespaceSelector.MatchExpressions {
				lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
				prefixedNsSelector.MatchExpressions[i] = lsr
			}

			// Empty namespace selector selects all namespaces (i.e., a namespace
			// label exists).
			if len(egressRule.NamespaceSelector.MatchLabels) == 0 && len(egressRule.NamespaceSelector.MatchExpressions) == 0 {
				prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
			}

			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", prefixedNsSelector, egressRule.PodSelector))
		} else if egressRule.PodSelector != nil {
			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", egressRule.PodSelector))
		} else {
			return nil, fmt.Errorf("CiliumEgressGatewayPolicy cannot have both nil namespace selector and nil pod selector")
		}
	}

	return &PolicyConfig{
		endpointSelectors: endpointSelectorList,
		dstCIDRs:          dstCidrList,
		excludedCIDRs:     excludedCIDRs,
		matchedEndpoints:  make(map[endpointID]*endpointMetadata),
		policyGwConfig:    policyGwc,
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseCEGPConfigID takes a CiliumEgressGatewayPolicy CR and returns only the config id
func ParseCEGPConfigID(cegp *v2.CiliumEgressGatewayPolicy) types.NamespacedName {
	return policyID{
		Name: cegp.Name,
	}
}
