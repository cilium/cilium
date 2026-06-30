// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"
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
