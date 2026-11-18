// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

// ServiceBackends describes the DNS server backends of a Kubernetes service.
type ServiceBackends struct {
	// PodSelector is the pod selector of the service. Empty for selectorless services.
	PodSelector map[string]string
	// IPs of the backends. Only set for selectorless services.
	IPs []string
	// Ports are the backend ports that the requested service ports translate to.
	Ports []api.PortProtocol
}

// Equal returns true if both ServiceBackends are identical.
func (b ServiceBackends) Equal(o ServiceBackends) bool {
	return maps.Equal(b.PodSelector, o.PodSelector) &&
		slices.Equal(b.IPs, o.IPs) &&
		slices.Equal(b.Ports, o.Ports)
}

// ServiceResolver looks up the backends of a Kubernetes service. servicePorts are
// the service (frontend) ports to translate to backend ports.
type ServiceResolver func(namespace, name string, servicePorts []uint16) ServiceBackends

// DNSServerRule allows DNS traffic to a set of DNS servers on the given ports.
type DNSServerRule struct {
	L3 types.Selectors
	L4 api.PortRules
}

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

// DNSServerRules returns the rules allowing traffic to the configured DNS servers,
// with dnsRules attached so that the traffic is inspected by the DNS proxy.
//
// Configured IPs are allowed on the configured ports. For the configured service,
// the configured ports are service ports. They are translated to the backend
// ports, since policy is enforced after service translation.
//
// The pods of the configured service run in the local cluster. If clusterName is
// not empty, the pod selector is restricted to that cluster, the same way as
// other pod selectors in policies. An empty clusterName selects any cluster.
func (cfg FQDNPolicyDNSServerConfig) DNSServerRules(resolver ServiceResolver, dnsRules api.PortRulesDNS, clusterName string) []DNSServerRule {
	var rules []DNSServerRule

	// Ports and the service reference are validated at startup, so errors are not expected here.
	ports, err := cfg.Ports()
	if err != nil {
		return nil
	}

	if cfg.FQDNPolicyDNSServerService != "" && resolver != nil {
		if ns, name, err := ParseServiceRef(cfg.FQDNPolicyDNSServerService); err == nil {
			backends := resolver(ns, name, ports)

			var l3 types.Selectors
			if len(backends.PodSelector) > 0 {
				matchLabels := make(map[string]slim_metav1.MatchLabelsValue, len(backends.PodSelector)+2)
				for k, v := range backends.PodSelector {
					matchLabels[k] = slim_metav1.MatchLabelsValue(v)
				}
				matchLabels[k8sConst.PodNamespaceLabel] = slim_metav1.MatchLabelsValue(ns)
				if clusterName != "" {
					matchLabels[k8sConst.PolicyLabelCluster] = slim_metav1.MatchLabelsValue(clusterName)
				}
				podSel := api.NewESFromK8sLabelSelector(
					labels.LabelSourceK8sKeyPrefix,
					&slim_metav1.LabelSelector{
						MatchLabels: matchLabels,
					},
				)
				l3 = append(l3, types.NewLabelSelector(podSel))
			}
			for _, ip := range backends.IPs {
				l3 = append(l3, types.ToSelector(api.CIDR(ip)))
			}

			// Without backend ports there is no DNS server to allow.
			if len(l3) > 0 && len(backends.Ports) > 0 {
				rules = append(rules, DNSServerRule{
					L3: l3,
					L4: api.PortRules{{Ports: backends.Ports, Rules: &api.L7Rules{DNS: dnsRules}}},
				})
			}
		}
	}

	if len(cfg.FQDNPolicyDNSServerIPs) > 0 {
		l3 := make(types.Selectors, 0, len(cfg.FQDNPolicyDNSServerIPs))
		for _, ip := range cfg.FQDNPolicyDNSServerIPs {
			l3 = append(l3, types.ToSelector(api.CIDR(ip)))
		}
		pps := make([]api.PortProtocol, 0, 2*len(ports))
		for _, port := range ports {
			portString := strconv.FormatUint(uint64(port), 10)
			pps = append(pps,
				api.PortProtocol{Port: portString, Protocol: api.ProtoUDP},
				api.PortProtocol{Port: portString, Protocol: api.ProtoTCP},
			)
		}
		rules = append(rules, DNSServerRule{
			L3: l3,
			L4: api.PortRules{{Ports: pps, Rules: &api.L7Rules{DNS: dnsRules}}},
		})
	}

	return rules
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
