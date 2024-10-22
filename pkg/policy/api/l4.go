// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/proxy/pkg/policy/api/kafka"
)

// L4Proto is a layer 4 protocol name
type L4Proto string

const (
	// Keep pkg/u8proto up-to-date with any additions here

	ProtoTCP    L4Proto = "TCP"
	ProtoUDP    L4Proto = "UDP"
	ProtoSCTP   L4Proto = "SCTP"
	ProtoICMP   L4Proto = "ICMP"
	ProtoICMPv6 L4Proto = "ICMPV6"
	ProtoAny    L4Proto = "ANY"

	PortProtocolAny = "0/ANY"
)

// IsAny returns true if an L4Proto represents ANY protocol
func (l4 L4Proto) IsAny() bool {
	return l4 == ProtoAny || string(l4) == ""
}

// PortProtocol specifies an L4 port with an optional transport protocol
type PortProtocol struct {
	// Port can be an L4 port number, or a name in the form of "http"
	// or "http-8080".
	//
	// +kubebuilder:validation:Pattern=`^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})|([a-zA-Z0-9]-?)*[a-zA-Z](-?[a-zA-Z0-9])*$`
	Port string `json:"port"`

	// EndPort can only be an L4 port number.
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	EndPort int32 `json:"endPort,omitempty"`

	// Protocol is the L4 protocol. If omitted or empty, any protocol
	// matches. Accepted values: "TCP", "UDP", "SCTP", "ANY"
	//
	// Matching on ICMP is not supported.
	//
	// Named port specified for a container may narrow this down, but may not
	// contradict this.
	//
	// +kubebuilder:validation:Enum=TCP;UDP;SCTP;ANY
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
		return p.Protocol.IsAny()
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

// EnvoyConfig defines a reference to a CiliumEnvoyConfig or CiliumClusterwideEnvoyConfig
type EnvoyConfig struct {
	// Kind is the resource type being referred to. Defaults to CiliumEnvoyConfig or
	// CiliumClusterwideEnvoyConfig for CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy,
	// respectively. The only case this is currently explicitly needed is when referring to a
	// CiliumClusterwideEnvoyConfig from CiliumNetworkPolicy, as using a namespaced listener
	// from a cluster scoped policy is not allowed.
	//
	// +kubebuilder:validation:Enum=CiliumEnvoyConfig;CiliumClusterwideEnvoyConfig
	// +kubebuilder:validation:Optional
	Kind string `json:"kind"`

	// Name is the resource name of the CiliumEnvoyConfig or CiliumClusterwideEnvoyConfig where
	// the listener is defined in.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// Listener defines a reference to an Envoy listener specified in a CEC or CCEC resource.
type Listener struct {
	// EnvoyConfig is a reference to the CEC or CCEC resource in which
	// the listener is defined.
	//
	// +kubebuilder:validation:Required
	EnvoyConfig *EnvoyConfig `json:"envoyConfig"`

	// Name is the name of the listener.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Priority for this Listener that is used when multiple rules would apply different
	// listeners to a policy map entry. Behavior of this is implementation dependent.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:validation:Optional
	Priority uint16 `json:"priority"`
}

// PortRule is a list of ports/protocol combinations with optional Layer 7
// rules which must be met.
type PortRule struct {
	// Ports is a list of L4 port/protocol
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=40
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

	// ServerNames is a list of allowed TLS SNI values. If not empty, then
	// TLS must be present and one of the provided SNIs must be indicated in the
	// TLS handshake.
	//
	// +kubebuilder:validation:Optional
	ServerNames []string `json:"serverNames,omitempty"`

	// listener specifies the name of a custom Envoy listener to which this traffic should be
	// redirected to.
	//
	// +kubebuilder:validation:Optional
	Listener *Listener `json:"listener,omitempty"`

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
	// +kubebuilder:validation:OneOf
	HTTP []PortRuleHTTP `json:"http,omitempty"`

	// Kafka-specific rules.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	Kafka []kafka.PortRule `json:"kafka,omitempty"`

	// DNS-specific rules.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
	DNS []PortRuleDNS `json:"dns,omitempty"`

	// Name of the L7 protocol for which the Key-value pair rules apply.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:OneOf
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

// IsEmpty returns whether the `L7Rules` is nil or contains no rules.
func (rules *L7Rules) IsEmpty() bool {
	return rules.Len() == 0
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
