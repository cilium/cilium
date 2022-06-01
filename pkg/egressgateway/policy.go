// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
	egressIP     net.IP
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
	egressIP net.IPNet
	// gatewayIP is the node internal IP of the gateway
	gatewayIP net.IP

	// localNodeConfiguredAsGateway tells if the local node is configured to
	// act as an egress gateway node for this config.
	// This information is used to decide if it is necessary to install ENI
	// IP rules/routes
	localNodeConfiguredAsGateway bool
}

// PolicyConfig is the internal representation of Cilium Egress NAT Policy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []*net.IPNet
	egressIP          net.IP

	policyGwConfig *policyGatewayConfig

	gatewayConfig gatewayConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// selectsEndpoint determines if the given endpoint is selected by the policy
// config based on matching labels of config and endpoint.
func (config *PolicyConfig) selectsEndpoint(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

func (config *policyGatewayConfig) selectsNodeAsGateway(node nodeTypes.Node) bool {
	return config.nodeSelector.Matches(k8sLabels.Set(node.Labels))
}

func (config *PolicyConfig) regenerateGatewayConfig(manager *Manager) {
	if config.egressIP != nil {
		config.gatewayConfig = gatewayConfig{
			gatewayIP: config.egressIP,
			egressIP:  net.IPNet{IP: config.egressIP, Mask: net.CIDRMask(32, 32)},
		}

		return
	}

	gwc := gatewayConfig{
		egressIP: net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 0)},
	}

	policyGwc := config.policyGwConfig

	for _, node := range manager.nodes {
		if !policyGwc.selectsNodeAsGateway(node) {
			continue
		}

		gwc.gatewayIP = node.GetK8sNodeIP()

		if node.IsLocal() {
			err := gwc.deriveFromPolicyGatewayConfig(policyGwc)
			if err != nil {
				logger := log.WithFields(logrus.Fields{
					logfields.CiliumEgressNATPolicyName: config.id,
					logfields.Interface:                 policyGwc.iface,
					logfields.EgressIP:                  policyGwc.egressIP,
				})

				logger.WithError(err).Error("Failed to derive policy gateway configuration")
			}
		}
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
	case gc.egressIP != nil && !gc.egressIP.Equal(net.IPv4zero):
		// If the gateway config specifies an egress IP, use the interface with that IP as egress
		// interface
		gwc.egressIP.IP = gc.egressIP
		gwc.ifaceName, gwc.ifaceIndex, gwc.egressIP.Mask, err = getIfaceWithIPv4Address(gc.egressIP)
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

func (config *PolicyConfig) forEachEndpointAndDestination(epDataStore map[endpointID]*endpointMetadata,
	f func(net.IP, *net.IPNet, *gatewayConfig)) {

	for _, endpoint := range epDataStore {
		if !config.selectsEndpoint(endpoint) {
			continue
		}

		for _, endpointIP := range endpoint.ips {
			for _, dstCIDR := range config.dstCIDRs {
				f(endpointIP, dstCIDR, &config.gatewayConfig)
			}
		}
	}
}

func (config *PolicyConfig) matches(epDataStore map[endpointID]*endpointMetadata,
	f func(net.IP, *net.IPNet, *gatewayConfig) bool) bool {

	for _, endpoint := range epDataStore {
		if !config.selectsEndpoint(endpoint) {
			continue
		}

		for _, endpointIP := range endpoint.ips {
			for _, dstCIDR := range config.dstCIDRs {
				if f(endpointIP, dstCIDR, &config.gatewayConfig) {
					return true
				}
			}
		}
	}

	return false
}

// ParseCENP takes a CiliumEgressNATPolicy CR and converts to PolicyConfig,
// the internal representation of the egress nat policy
func ParseCENP(cenp *v2alpha1.CiliumEgressNATPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []*net.IPNet

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := cenp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("CiliumEgressNATPolicy must have a name")
	}

	log.WithFields(logrus.Fields{logfields.CiliumEgressNATPolicyName: name}).Warn("CiliumEgressNATPolicy is deprecated and will be removed in version 1.13. Use CiliumEgressGatewayPolicy instead.")

	for _, cidrString := range cenp.Spec.DestinationCIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumEgressNATPolicyName: name}).Warn("Error parsing cidr.")
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, egressRule := range cenp.Spec.Egress {
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
			return nil, fmt.Errorf("CiliumEgressNATPolicy cannot have both nil namespace selector and nil pod selector")
		}
	}

	return &PolicyConfig{
		endpointSelectors: endpointSelectorList,
		dstCIDRs:          dstCidrList,
		egressIP:          net.ParseIP(cenp.Spec.EgressSourceIP).To4(),
		policyGwConfig:    nil,
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseCENPConfigID takes a CiliumEgressNATPolicy CR and returns only the config id
func ParseCENPConfigID(cenp *v2alpha1.CiliumEgressNATPolicy) types.NamespacedName {
	return policyID{
		Name: cenp.Name,
	}
}

// ParseCEGP takes a CiliumEgressGatewayPolicy CR and converts to PolicyConfig,
// the internal representation of the egress gateway policy
func ParseCEGP(cegp *v2.CiliumEgressGatewayPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []*net.IPNet

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

	policyGwc := &policyGatewayConfig{
		nodeSelector: api.NewESFromK8sLabelSelector("", egressGateway.NodeSelector),
		iface:        egressGateway.Interface,
		egressIP:     net.ParseIP(egressGateway.EgressIP),
	}

	for _, cidrString := range cegp.Spec.DestinationCIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumEgressGatewayPolicyName: name}).Warn("Error parsing cidr.")
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
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
		egressIP:          nil,
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
