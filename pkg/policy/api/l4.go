// Copyright 2016-2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/policy/api/kafka"
)

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
	// Port can also be a port name, which must contain at least one [a-z],
	// and may also contain [0-9] and '-' anywhere except adjacent to another
	// '-' or in the beginning or the end.
	//
	// +kubebuilder:validation:Pattern=`^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})|([a-zA-Z0-9]-?)*[a-zA-Z](-?[a-zA-Z0-9])*$`
	Port string `json:"port"`

	// Protocol is the L4 protocol. If omitted or empty, any protocol
	// matches. Accepted values: "TCP", "UDP", ""/"ANY"
	//
	// Matching on ICMP is not supported.
	//
	// Named port specified for a container may narrow this down, but may not
	// contradict this.
	//
	// +kubebuilder:validation:Enum=TCP;UDP;ANY
	// +kubebuilder:validation:Optional
	Protocol L4Proto `json:"protocol,omitempty"`
}

// Covers returns true if the ports and protocol specified in the received
// PortProtocol are equal to or a superset of the ports and protocol in 'other'.
// Named ports only cover other named ports with exactly the same name.
func (p PortProtocol) Covers(other PortProtocol) bool {
	if p.Port != other.Port {
		return false
	}
	if p.Protocol != other.Protocol {
		return p.Protocol == "" || p.Protocol == ProtoAny
	}
	return true
}

// Secret is a reference to a secret, backed by k8s or local file system.
type Secret struct {
	// Namespace is the namespace in which the secret exists. Context of use
	// determines the default value if left out (e.g., "default").
	//
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// Name is the name of the secret.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// TLSContext provides TLS configuration via reference to either k8s secrets
// or via filepath. If both are set, directory is given priority over
// k8sSecrets.
type TLSContext struct {
	// Secret is the secret that contains the certificates and private key for
	// the TLS context.
	// By default, Cilium will search in this secret for the following items:
	//  - 'ca.crt'  - Which represents the trusted CA to verify remote source.
	//  - 'tls.crt' - Which represents the public key certificate.
	//  - 'tls.key' - Which represents the private key matching the public key
	//                certificate.
	//
	// +kubebuilder:validation:Required
	Secret *Secret `json:"secret"`

	// TrustedCA is the file name or k8s secret item name for the trusted CA.
	// If omitted, 'ca.crt' is assumed, if it exists. If given, the item must
	// exist.
	//
	// +kubebuilder:validation:Optional
	TrustedCA string `json:"trustedCA,omitempty"`

	// Certificate is the file name or k8s secret item name for the certificate
	// chain. If omitted, 'tls.crt' is assumed, if it exists. If given, the
	// item must exist.
	//
	// +kubebuilder:validation:Optional
	Certificate string `json:"certificate,omitempty"`

	// PrivateKey is the file name or k8s secret item name for the private key
	// matching the certificate chain. If omitted, 'tls.key' is assumed, if it
	// exists. If given, the item must exist.
	//
	// +kubebuilder:validation:Optional
	PrivateKey string `json:"privateKey,omitempty"`
}

// PortRule is a list of ports/protocol combinations with optional Layer 7
// rules which must be met.
type PortRule struct {
	// Ports is a list of L4 port/protocol
	//
	// +kubebuilder:validation:Optional
	Ports []PortProtocol `json:"ports,omitempty"`

	// TerminatingTLS is the TLS context for the connection terminated by
	// the L7 proxy.  For egress policy this specifies the server-side TLS
	// parameters to be applied on the connections originated from the local
	// endpoint and terminated by the L7 proxy. For ingress policy this specifies
	// the server-side TLS parameters to be applied on the connections
	// originated from a remote source and terminated by the L7 proxy.
	//
	// +kubebuilder:validation:Optional
	TerminatingTLS *TLSContext `json:"terminatingTLS,omitempty"`

	// OriginatingTLS is the TLS context for the connections originated by
	// the L7 proxy.  For egress policy this specifies the client-side TLS
	// parameters for the upstream connection originating from the L7 proxy
	// to the remote destination. For ingress policy this specifies the
	// client-side TLS parameters for the connection from the L7 proxy to
	// the local endpoint.
	//
	// +kubebuilder:validation:Optional
	OriginatingTLS *TLSContext `json:"originatingTLS,omitempty"`

	// Rules is a list of additional port level rules which must be met in
	// order for the PortRule to allow the traffic. If omitted or empty,
	// no layer 7 rules are enforced.
	//
	// +kubebuilder:validation:Optional
	Rules *L7Rules `json:"rules,omitempty"`
}

// GetPortProtocols returns the Ports field of the PortRule.
func (pd PortRule) GetPortProtocols() []PortProtocol {
	return pd.Ports
}

// GetPortRule returns the PortRule.
func (pd *PortRule) GetPortRule() *PortRule {
	return pd
}

// PortDenyRule is a list of ports/protocol that should be used for deny
// policies. This structure lacks the L7Rules since it's not supported in deny
// policies.
type PortDenyRule struct {
	// Ports is a list of L4 port/protocol
	//
	// +kubebuilder:validation:Optional
	Ports []PortProtocol `json:"ports,omitempty"`
}

// GetPortProtocols returns the Ports field of the PortDenyRule.
func (pd PortDenyRule) GetPortProtocols() []PortProtocol {
	return pd.Ports
}

// GetPortRule returns nil has it is not a PortRule.
func (pd *PortDenyRule) GetPortRule() *PortRule {
	return nil
}

// L7Rules is a union of port level rule types. Mixing of different port
// level rule types is disallowed, so exactly one of the following must be set.
// If none are specified, then no additional port level rules are applied.
type L7Rules struct {
	// HTTP specific rules.
	//
	// +kubebuilder:validation:Optional
	HTTP []PortRuleHTTP `json:"http,omitempty"`

	// Kafka-specific rules.
	//
	// +kubebuilder:validation:Optional
	Kafka []kafka.PortRule `json:"kafka,omitempty"`

	// DNS-specific rules.
	//
	// +kubebuilder:validation:Optional
	DNS []PortRuleDNS `json:"dns,omitempty"`

	// Name of the L7 protocol for which the Key-value pair rules apply.
	//
	// +kubebuilder:validation:Optional
	L7Proto string `json:"l7proto,omitempty"`

	// Key-value pair rules.
	//
	// +kubebuilder:validation:Optional
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

// PortRules is a slice of PortRule.
type PortRules []PortRule

// Iterate iterates over all elements of PortRules.
func (pr PortRules) Iterate(f func(pr Ports) error) error {
	for i := range pr {
		err := f(&pr[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// Len returns the length of the elements of PortRules.
func (pr PortRules) Len() int {
	return len(pr)
}

// PortDenyRules is a slice of PortDenyRule.
type PortDenyRules []PortDenyRule

// Iterate iterates over all elements of PortDenyRules.
func (pr PortDenyRules) Iterate(f func(pr Ports) error) error {
	for i := range pr {
		err := f(&pr[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// Len returns the length of the elements of PortDenyRules.
func (pr PortDenyRules) Len() int {
	return len(pr)
}

// Ports is an interface that should be used by all implementations of the
// PortProtocols.
type Ports interface {
	// GetPortProtocols returns the slice PortProtocol
	GetPortProtocols() []PortProtocol
	// GetPortRule returns a PortRule, if the implementation does not support
	// it, then returns nil.
	GetPortRule() *PortRule
}

// PortsIterator is an interface that should be implemented by structures that
// can iterate over a list of Ports interfaces.
type PortsIterator interface {
	Iterate(f func(pr Ports) error) error
	Len() int
}
