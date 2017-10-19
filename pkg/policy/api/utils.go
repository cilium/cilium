// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/cilium/common/types"
)

// Len returns the total number of rules inside `L7Rules`.
func (rules *L7Rules) Len() int {
	return len(rules.HTTP) + len(rules.Kafka)
}

// Exists returns true if the HTTP rule already exists in the list of rules
func (h *PortRuleHTTP) Exists(rules L7Rules) bool {
	for _, existingRule := range rules.HTTP {
		if h.Equal(existingRule) {
			return true
		}
	}

	return false
}

// Equal returns true if both HTTP rules are equal
func (h *PortRuleHTTP) Equal(o PortRuleHTTP) bool {
	if h.Path != o.Path ||
		h.Method != o.Method ||
		h.Host != o.Host ||
		len(h.Headers) != len(o.Headers) {
		return false
	}

	for i, value := range h.Headers {
		if o.Headers[i] != value {
			return false
		}
	}
	return true
}

// Exists returns true if the HTTP rule already exists in the list of rules
func (k *PortRuleKafka) Exists(rules L7Rules) bool {
	for _, existingRule := range rules.Kafka {
		if k.Equal(existingRule) {
			return true
		}
	}

	return false
}

// Equal returns true if both HTTP rules are equal
func (k *PortRuleKafka) Equal(o PortRuleKafka) bool {
	return k.APIVersion == o.APIVersion && k.APIKey == o.APIKey && k.Topic == o.Topic
}

// Validate returns an error if the layer 4 protocol is not valid
func (l4 L4Proto) Validate() error {
	switch l4 {
	case ProtoAny, ProtoTCP, ProtoUDP:
	default:
		return fmt.Errorf("invalid protocol %q, must be { tcp | udp | any }", l4)
	}

	return nil
}

// NumRules returns the total number of L7Rules configured in this PortRule
func (r *PortRule) NumRules() int {
	if r.Rules == nil {
		return 0
	}

	return r.Rules.Len()
}

// ParseL4Proto parses a string as layer 4 protocol
func ParseL4Proto(proto string) (L4Proto, error) {
	if proto == "" {
		return ProtoAny, nil
	}

	p := L4Proto(strings.ToUpper(proto))
	return p, p.Validate()
}

// GenerateToServiceRulesFromEndpoint populates egress rule with ToCIDR and ToPorts rules based on ToServices defined in egress rule and provided endpoint
func (e *EgressRule) GenerateToServiceRulesFromEndpoint(serviceInfo types.K8sServiceNamespace, endpoint types.K8sServiceEndpoint) error {
	for _, service := range e.ToServices {
		// TODO: match services by labels
		if service.K8sService == K8sServiceNamespace(serviceInfo) {
			if err := generateToCidrFromEndpoint(e, endpoint); err != nil {
				return err
			}
			if err := generateToPortsFromEndpoint(e, endpoint); err != nil {
				return err
			}
		}
	}
	return nil
}

// generateToCidrFromEndpoint takes an egress rule and populates it with ToCIDR rules based on provided enpoint object
func generateToCidrFromEndpoint(egress *EgressRule, endpoint types.K8sServiceEndpoint) error {
	for ip := range endpoint.BEIPs {
		epIP := net.ParseIP(ip)
		// TODO: this will only work for IPv4. How to retrieve the mask from IPv6 address?
		mask := epIP.DefaultMask()

		found := false
		for _, c := range egress.ToCIDR {
			_, cidr, err := net.ParseCIDR(string(c))
			if err != nil {
				return err
			}
			if cidr.Contains(epIP) {
				found = true
				break
			}
		}
		if !found {
			cidr := net.IPNet{IP: epIP.Mask(mask), Mask: mask}
			egress.ToCIDR = append(egress.ToCIDR, CIDR(cidr.String()))
		}
	}
	return nil
}

// generateToPortsFromEndpoint takes an egress rule and populates it with ToPorts rules based on provided enpoint object
func generateToPortsFromEndpoint(egress *EgressRule, endpoint types.K8sServiceEndpoint) error {
	// additional port rule that will contain all endpoint ports
	portRule := PortRule{}
	for _, port := range endpoint.Ports {
		found := false
	loop:
		for _, portRule := range egress.ToPorts {
			for _, portProtocol := range portRule.Ports {
				numericPort, err := strconv.Atoi(portProtocol.Port)
				if err != nil {
					return err
				}

				if strings.ToLower(string(port.Protocol)) == strings.ToLower(string(portProtocol.Protocol)) && int(port.Port) == numericPort {
					found = true
					break loop
				}
			}
		}
		if !found {
			portRule.Ports = append(portRule.Ports, PortProtocol{
				Port:     strconv.Itoa(int(port.Port)),
				Protocol: L4Proto(strings.ToUpper(string(port.Protocol))),
			})
		}
	}

	if len(portRule.Ports) > 0 {
		egress.ToPorts = append(egress.ToPorts, portRule)
	}

	return nil
}

func (e *EgressRule) DeleteGeneratedToServiceRulesFromEndpoint(serviceInfo types.K8sServiceNamespace, endpoint types.K8sServiceEndpoint) error {
	for _, service := range e.ToServices {
		// TODO: match services by labels
		if service.K8sService == K8sServiceNamespace(serviceInfo) {
			if err := deleteToCidrFromEndpoint(e, endpoint); err != nil {
				return err
			}
			if err := deleteToPortsFromEndpoint(e, endpoint); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteToCidrFromEndpoint takes an egress rule and removes ToCIDR rules matching endpoint
func deleteToCidrFromEndpoint(egress *EgressRule, endpoint types.K8sServiceEndpoint) error {
	newToCIDR := make([]CIDR, 0, len(egress.ToCIDR))

	for ip := range endpoint.BEIPs {
		epIP := net.ParseIP(ip)
		for _, c := range egress.ToCIDR {
			_, cidr, err := net.ParseCIDR(string(c))
			if err != nil {
				return err
			}
			if !cidr.Contains(epIP) {
				//if endpoint is not in CIDR it's ok to retain it
				newToCIDR = append(newToCIDR, c)
			}
		}
	}

	egress.ToCIDR = newToCIDR

	return nil
}

// deleteToPortsFromEndpoint takes an egress rule and removes ToPorts rules matching endpoint
func deleteToPortsFromEndpoint(egress *EgressRule, endpoint types.K8sServiceEndpoint) error {
	newPortRules := make([]PortRule, 0, len(egress.ToPorts))

	for _, port := range endpoint.Ports {
		for _, portRule := range egress.ToPorts {
			for _, portProtocol := range portRule.Ports {
				numericPort, err := strconv.Atoi(portProtocol.Port)
				if err != nil {
					return err
				}

				if !(strings.ToLower(string(port.Protocol)) == strings.ToLower(string(portProtocol.Protocol)) && int(port.Port) == numericPort) {
					newPortRules = append(newPortRules, portRule)
				}
			}
		}
	}

	egress.ToPorts = newPortRules

	return nil
}
