// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"strconv"

	"github.com/spf13/pflag"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

type FQDNPolicyDNSServerConfig struct {
	FQDNPolicyDNSServerIPs       []string          `mapstructure:"fqdn-policy-dns-server-ips"`
	FQDNPolicyDNSServerNamespace string            `mapstructure:"fqdn-policy-dns-server-namespace"`
	FQDNPolicyDNSServerPodLabel  map[string]string `mapstructure:"fqdn-policy-dns-server-pod-label"`
	FQDNPolicyDNSServerPort      int               `mapstructure:"fqdn-policy-dns-server-port"`
}

var DefaultFQDNPolicyDNSServerConfig = FQDNPolicyDNSServerConfig{
	FQDNPolicyDNSServerPort: 53,
}

func (cfg FQDNPolicyDNSServerConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("fqdn-policy-dns-server-ips", cfg.FQDNPolicyDNSServerIPs, "Comma-separated list of IP addresses of DNS servers for FQDN policy resolution")
	flags.String("fqdn-policy-dns-server-namespace", cfg.FQDNPolicyDNSServerNamespace, "Namespace of DNS server pods for FQDN policy resolution")
	flags.StringToString("fqdn-policy-dns-server-pod-label", cfg.FQDNPolicyDNSServerPodLabel, "Label of DNS server pods for FQDN policy resolution")
	flags.Int("fqdn-policy-dns-server-port", cfg.FQDNPolicyDNSServerPort, "Port of DNS server pods for FQDN policy resolution")
}

// DNSSelectors creates and returns the pod or IP selectors targeting allowed DNS servers
// for FQDN policies, along with the fully constructed L4 PortRules containing the allowed FQDN rules.
func (cfg FQDNPolicyDNSServerConfig) DNSSelectors(dnsRules api.PortRulesDNS) (types.Selectors, api.PortRules) {
	var dnsSelectors types.Selectors

	// Add Pod Selector based on config.
	if len(cfg.FQDNPolicyDNSServerPodLabel) > 0 {
		matchLabels := make(map[string]slim_metav1.MatchLabelsValue, len(cfg.FQDNPolicyDNSServerPodLabel))
		for k, v := range cfg.FQDNPolicyDNSServerPodLabel {
			matchLabels[k] = slim_metav1.MatchLabelsValue(v)
		}

		if cfg.FQDNPolicyDNSServerNamespace != "" {
			matchLabels[k8sConst.PodNamespaceLabel] = slim_metav1.MatchLabelsValue(cfg.FQDNPolicyDNSServerNamespace)
		}

		podSelector := api.NewESFromK8sLabelSelector(
			labels.LabelSourceK8sKeyPrefix,
			&slim_metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		)
		dnsSelectors = append(dnsSelectors, types.ToSelector(podSelector))
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
