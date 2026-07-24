// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"
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
