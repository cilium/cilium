// Copyright 2016-2019 Authors of Cilium
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

// L4Proto is a layer 4 protocol name
type L4Proto string

const (
	// Keep pkg/u8proto up-to-date with any additions here

	ProtoTCP L4Proto = "TCP"
	ProtoUDP L4Proto = "UDP"
	ProtoAny L4Proto = "ANY"

	PortProtocolAny = "0/ANY"
)

// PortProtocol specifies an L4 port with an optional transport protocol
type PortProtocol struct {
	// Port is an L4 port number. For now the string will be strictly
	// parsed as a single uint16. In the future, this field may support
	// ranges in the form "1024-2048
	Port string `json:"port"`

	// Protocol is the L4 protocol. If omitted or empty, any protocol
	// matches. Accepted values: "TCP", "UDP", ""/"ANY"
	//
	// Matching on ICMP is not supported.
	//
	// +optional
	Protocol L4Proto `json:"protocol,omitempty"`
}

// Covers returns true if the ports and protocol specified in the received
// PortProtocol are equal to or a superset of the ports and protocol in 'other'.
func (p PortProtocol) Covers(other PortProtocol) bool {
	if p.Port != other.Port {
		return false
	}
	if p.Protocol != other.Protocol {
		return p.Protocol == "" || p.Protocol == ProtoAny
	}
	return true
}

// PortRule is a list of ports/protocol combinations with optional Layer 7
// rules which must be met.
type PortRule struct {
	// Ports is a list of L4 port/protocol
	//
	// If omitted or empty but RedirectPort is set, then all ports of the
	// endpoint subject to either the ingress or egress rule are being
	// redirected.
	//
	// +optional
	Ports []PortProtocol `json:"ports,omitempty"`

	// Rules is a list of additional port level rules which must be met in
	// order for the PortRule to allow the traffic. If omitted or empty,
	// no layer 7 rules are enforced.
	//
	// +optional
	Rules *L7Rules `json:"rules,omitempty"`
}

// L7Rules is a union of port level rule types. Mixing of different port
// level rule types is disallowed, so exactly one of the following must be set.
// If none are specified, then no additional port level rules are applied.
type L7Rules struct {
	// HTTP specific rules.
	//
	// +optional
	HTTP []PortRuleHTTP `json:"http,omitempty"`

	// Kafka-specific rules.
	//
	// +optional
	Kafka []PortRuleKafka `json:"kafka,omitempty"`

	// DNS-specific rules.
	//
	// +optional
	DNS []PortRuleDNS `json:"dns,omitempty"`

	// Name of the L7 protocol for which the Key-value pair rules apply
	//
	// +optional
	L7Proto string `json:"l7proto,omitempty"`

	// Key-value pair rules
	//
	// +optional
	L7 []PortRuleL7 `json:"l7,omitempty"`
}

// Len returns the total number of rules inside `L7Rules`.
// Returns 0 if nil.
func (rules *L7Rules) Len() int {
	if rules == nil {
		return 0
	}
	return len(rules.HTTP) + len(rules.Kafka) + len(rules.DNS) + len(rules.L7)
}

// IsEmpty returns whether the `L7Rules` is nil or contains nil rules.
func (rules *L7Rules) IsEmpty() bool {
	return rules == nil || (rules.HTTP == nil && rules.Kafka == nil && rules.DNS == nil && rules.L7 == nil)
}
