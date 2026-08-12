// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"strings"

	"github.com/spf13/pflag"
)

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
