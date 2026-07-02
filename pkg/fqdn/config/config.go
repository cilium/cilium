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

type FQDNPolicyDNSLookupConfig struct {
	// FQDNPolicyDNSLookupIPs specifies a list of IP addresses for DNS lookups in FQDN policies.
	FQDNPolicyDNSLookupIPs []string `mapstructure:"fqdn-policy-dns-lookup-ips"`
	// FQDNPolicyDNSLookupNamespace specifies the namespace for DNS pod lookups in FQDN policies.
	FQDNPolicyDNSLookupNamespace string `mapstructure:"fqdn-policy-dns-lookup-namespace"`
	// FQDNPolicyDNSLookupPodLabels specifies the pod labels for DNS lookups in FQDN policies.
	FQDNPolicyDNSLookupPodLabels map[string]string `mapstructure:"fqdn-policy-dns-lookup-pod-labels"`
	// FQDNPolicyDNSLookupPort specifies the port for DNS lookups in FQDN policies.
	FQDNPolicyDNSLookupPort int `mapstructure:"fqdn-policy-dns-lookup-port"`
}

var DefaultFQDNPolicyDNSLookupConfig = FQDNPolicyDNSLookupConfig{
	FQDNPolicyDNSLookupIPs:       nil,
	FQDNPolicyDNSLookupNamespace: "kube-system",
	FQDNPolicyDNSLookupPodLabels: map[string]string{"k8s-app": "kube-dns"},
	FQDNPolicyDNSLookupPort:      53,
}

var GlobalFQDNPolicyDNSLookupConfig = DefaultFQDNPolicyDNSLookupConfig

func (def FQDNPolicyDNSLookupConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("fqdn-policy-dns-lookup-ips", def.FQDNPolicyDNSLookupIPs, "Comma-separated list of IP addresses for DNS lookups in FQDN policies")
	flags.String("fqdn-policy-dns-lookup-namespace", def.FQDNPolicyDNSLookupNamespace, "Namespace for DNS pod lookups in FQDN policies")
	flags.StringToString("fqdn-policy-dns-lookup-pod-labels", def.FQDNPolicyDNSLookupPodLabels, "Pod labels for DNS lookups in FQDN policies")
	flags.Int("fqdn-policy-dns-lookup-port", def.FQDNPolicyDNSLookupPort, "Port for DNS lookups in FQDN policies")
}

// GetFQDNPolicyDNSSelectors creates and returns the pod or IP selectors targeting allowed DNS servers
// for FQDN policies, along with the fully constructed L4 PortRules containing the allowed FQDN rules.
func GetFQDNPolicyDNSSelectors(dnsRules api.PortRulesDNS) (types.Selectors, api.PortRules) {
	var dnsSelectors types.Selectors

	cfg := GlobalFQDNPolicyDNSLookupConfig

	// Add Pod Selector based on config.
	if len(cfg.FQDNPolicyDNSLookupPodLabels) > 0 {
		matchLabels := make(map[string]slim_metav1.MatchLabelsValue, len(cfg.FQDNPolicyDNSLookupPodLabels))
		for k, v := range cfg.FQDNPolicyDNSLookupPodLabels {
			matchLabels[k] = slim_metav1.MatchLabelsValue(v)
		}

		if cfg.FQDNPolicyDNSLookupNamespace != "" {
			matchLabels[k8sConst.PodNamespaceLabel] = slim_metav1.MatchLabelsValue(cfg.FQDNPolicyDNSLookupNamespace)
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
	if len(cfg.FQDNPolicyDNSLookupIPs) > 0 {
		for _, ip := range cfg.FQDNPolicyDNSLookupIPs {
			dnsSelectors = append(dnsSelectors, types.ToSelector(api.CIDR(ip)))
		}
	}

	portString := strconv.Itoa(cfg.FQDNPolicyDNSLookupPort)
	portRules := api.PortRules{{
		Ports: []api.PortProtocol{
			{Port: portString, Protocol: api.ProtoUDP},
			{Port: portString, Protocol: api.ProtoTCP},
		},
		Rules: &api.L7Rules{DNS: dnsRules},
	}}

	return dnsSelectors, portRules
}
