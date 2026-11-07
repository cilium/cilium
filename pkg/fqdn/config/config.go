// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

// ServiceResolver retrieves pod labels or backend IPs for a given Kubernetes service.
type ServiceResolver func(namespace, name string) (podSelector map[string]string, ips []string)

type FQDNPolicyDNSServerConfig struct {
	FQDNPolicyDNSServerIPs     []string `mapstructure:"fqdn-policy-dns-server-ips"`
	FQDNPolicyDNSServerService string   `mapstructure:"fqdn-policy-dns-server-service"`
	FQDNPolicyDNSServerPort    int      `mapstructure:"fqdn-policy-dns-server-port"`
}

var DefaultFQDNPolicyDNSServerConfig = FQDNPolicyDNSServerConfig{
	FQDNPolicyDNSServerPort: 53,
}

func (cfg FQDNPolicyDNSServerConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("fqdn-policy-dns-server-ips", cfg.FQDNPolicyDNSServerIPs, "Comma-separated list of IP addresses of DNS servers for FQDN policy resolution")
	flags.String("fqdn-policy-dns-server-service", cfg.FQDNPolicyDNSServerService, "K8s service (namespace/name) of DNS servers for FQDN policy resolution")
	flags.Int("fqdn-policy-dns-server-port", cfg.FQDNPolicyDNSServerPort, "Port of DNS server pods for FQDN policy resolution")
}

// DNSSelectors creates and returns the pod or IP selectors targeting allowed DNS servers
// for FQDN policies, along with the fully constructed L4 PortRules containing the allowed FQDN rules.
func (cfg FQDNPolicyDNSServerConfig) DNSSelectors(resolver ServiceResolver, dnsRules api.PortRulesDNS) (types.Selectors, api.PortRules) {
	var dnsSelectors types.Selectors

	// Add Service Selector based on config if resolver is provided
	if cfg.FQDNPolicyDNSServerService != "" && resolver != nil {
		ns, name := ParseServiceRef(cfg.FQDNPolicyDNSServerService)
		podSelector, ips := resolver(ns, name)

		if len(podSelector) > 0 {
			matchLabels := make(map[string]slim_metav1.MatchLabelsValue, len(podSelector))
			for k, v := range podSelector {
				matchLabels[k] = slim_metav1.MatchLabelsValue(v)
			}
			if ns != "" {
				matchLabels[k8sConst.PodNamespaceLabel] = slim_metav1.MatchLabelsValue(ns)
			}
			podSel := api.NewESFromK8sLabelSelector(
				labels.LabelSourceK8sKeyPrefix,
				&slim_metav1.LabelSelector{
					MatchLabels: matchLabels,
				},
			)
			dnsSelectors = append(dnsSelectors, types.NewLabelSelector(podSel))
		}

		for _, ip := range ips {
			dnsSelectors = append(dnsSelectors, types.ToSelector(api.CIDR(ip)))
		}
	}

	// Add IP Selectors if IPs are provided
	if len(cfg.FQDNPolicyDNSServerIPs) > 0 {
		for _, ip := range cfg.FQDNPolicyDNSServerIPs {
			dnsSelectors = append(dnsSelectors, types.ToSelector(api.CIDR(ip)))
		}
	}

	portString := strconv.Itoa(cfg.FQDNPolicyDNSServerPort)
	portRules := api.PortRules{{
		Ports: []api.PortProtocol{
			{Port: portString, Protocol: api.ProtoUDP},
			{Port: portString, Protocol: api.ProtoTCP},
		},
		Rules: &api.L7Rules{DNS: dnsRules},
	}}

	return dnsSelectors, portRules
}

// ParseServiceRef splits a service reference string ("namespace/name" or "name")
// into namespace and name components. If no namespace is specified in svcRef,
// it defaults to "kube-system" to prevent cross-namespace service lookup ambiguity.
func ParseServiceRef(svcRef string) (namespace, name string) {
	parts := strings.SplitN(svcRef, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "kube-system", parts[0]
}
