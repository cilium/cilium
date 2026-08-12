// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

type FQDNPolicyDNSServerConfig struct {
	FQDNPolicyDNSServerIPs     []string `mapstructure:"fqdn-policy-dns-server-ips"`
	FQDNPolicyDNSServerService string   `mapstructure:"fqdn-policy-dns-server-service"`
	FQDNPolicyDNSServerPorts   []string `mapstructure:"fqdn-policy-dns-server-ports"`
}

var DefaultFQDNPolicyDNSServerConfig = FQDNPolicyDNSServerConfig{
	FQDNPolicyDNSServerPorts: []string{"53"},
}

func (cfg FQDNPolicyDNSServerConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("fqdn-policy-dns-server-ips", cfg.FQDNPolicyDNSServerIPs, "Comma-separated list of IP addresses of DNS servers for FQDN policy resolution")
	flags.String("fqdn-policy-dns-server-service", cfg.FQDNPolicyDNSServerService, "K8s service (namespace/name) of DNS servers for FQDN policy resolution")
	flags.StringSlice("fqdn-policy-dns-server-ports", cfg.FQDNPolicyDNSServerPorts, "Comma-separated list of DNS server ports for FQDN policy resolution. Service ports are translated to backend ports")
}

// Validate checks that the configuration is well-formed.
func (cfg FQDNPolicyDNSServerConfig) Validate() error {
	if _, err := cfg.Ports(); err != nil {
		return fmt.Errorf("invalid fqdn-policy-dns-server-ports: %w", err)
	}
	for _, ip := range cfg.FQDNPolicyDNSServerIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("invalid fqdn-policy-dns-server-ips: %w", err)
		}
	}
	if cfg.FQDNPolicyDNSServerService == "" {
		return nil
	}
	if _, _, err := ParseServiceRef(cfg.FQDNPolicyDNSServerService); err != nil {
		return fmt.Errorf("invalid fqdn-policy-dns-server-service: %w", err)
	}
	return nil
}

// Ports parses the configured DNS server ports. At least one port is required.
// Port ranges are not supported, since DNS rules cannot be applied to them.
func (cfg FQDNPolicyDNSServerConfig) Ports() ([]uint16, error) {
	if len(cfg.FQDNPolicyDNSServerPorts) == 0 {
		return nil, errors.New("at least one port is required")
	}
	ports := make([]uint16, 0, len(cfg.FQDNPolicyDNSServerPorts))
	for _, s := range cfg.FQDNPolicyDNSServerPorts {
		p, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("port %q must be a number between 1 and 65535", s)
		}
		ports = append(ports, uint16(p))
	}
	return ports, nil
}

// ParseServiceRef splits a service reference string of the form "namespace/name"
// into its namespace and name components. Both components are required.
func ParseServiceRef(svcRef string) (namespace, name string, err error) {
	namespace, name, found := strings.Cut(svcRef, "/")
	if !found || namespace == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("service reference %q must be in the form namespace/name", svcRef)
	}
	return namespace, name, nil
}
