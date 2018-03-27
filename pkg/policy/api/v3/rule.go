// Copyright 2016-2018 Authors of Cilium
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

package v3

import (
	"github.com/cilium/cilium/pkg/labels"
)

// Rule is a policy rule which must be applied to all endpoints which match the
// labels contained in the identitySelector.
//
// Each rule is split into an ingress section which contains all rules
// applicable at ingress, and an egress section applicable at egress.
//
// Either ingress, egress, or both can be provided. If both ingress and egress
// are omitted, the rule has no effect.
type Rule struct {
	// IdentitySelector selects all endpoints which should be subject to
	// this rule. Cannot be empty.
	IdentitySelector IdentitySelector `json:"identitySelector"`

	// Ingress is a list of IngressRule which are enforced at ingress.
	// If omitted or empty, this rule does not apply at ingress.
	//
	// +optional
	Ingress []IngressRule `json:"ingress,omitempty"`

	// Egress is a list of EgressRule which are enforced at egress.
	// If omitted or empty, this rule does not apply at egress.
	//
	// +optional
	Egress []EgressRule `json:"egress,omitempty"`

	// Labels is a list of optional strings which can be used to
	// re-identify the rule or to store metadata. It is possible to lookup
	// or delete strings based on labels. Labels are not required to be
	// unique, multiple rules can have overlapping or identical labels.
	//
	// +optional
	Labels labels.LabelArray `json:"labels,omitempty"`

	// Description is a free form string, it can be used by the creator of
	// the rule to store human readable explanation of the purpose of this
	// rule. Rules cannot be identified by comment.
	//
	// +optional
	Description string `json:"description,omitempty"`
}

// IngressRule contains all rule types which can be applied at ingress,
// i.e. network traffic that originates outside of the endpoint and
// is entering the endpoint selected by the identitySelector.
//
// - All members of this structure are optional. If omitted or empty, the
//   member will have no effect on the rule.
//
// - If multiple members are set, all of them need to match in order for
//   the rule to take effect. The exception to this rule is FromRequires field;
//   the effects of any Requires field in any rule will apply to all other
//   rules as well.
type IngressRule struct {
	// FromIdentities is a list of identities, previously known as endpoints,
	// identified by an IdentitySelector which are allowed to communicate with
	// the endpoint subject to the rule.
	//
	// Example:
	// Any endpoint with the label "role=backend" can be consumed by any
	// endpoint carrying the label "role=frontend".
	//
	// +optional
	FromIdentities *IdentityRule `json:"fromIdentities,omitempty"`

	// FromRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be reachable. These additional
	// constraints do not by themselves grant access privileges and must always
	// be accompanied with at least one matching FromIdentities.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires consuming endpoint
	// to also carry the label "team=A".
	//
	// +optional
	FromRequires *IdentityRequirement `json:"fromRequires,omitempty"`

	// FromCIDRs is a list of IP blocks from which the endpoint subject to the
	// rule is allowed to receive connections in addition to FromEndpoints,
	// along with a list of subnets contained within their corresponding IP
	// block from which traffic should not be allowed.
	// This will match on the source IP address of incoming connections.
	//
	// Example:
	// Any endpoint with the label "app=my-legacy-pet" is allowed to receive
	// connections from 10.0.0.0/8 except from IPs in subnet 10.96.0.0/12.
	//
	// +optional
	FromCIDRs *CIDRRule `json:"fromCIDR,omitempty"`

	// FromEntities is a list of special entities from which the endpoint subject
	// to the rule is allowed to receive connections. Supported entities are
	// `world` and `host`.
	//
	// +optional
	FromEntities *EntityRule `json:"fromEntities,omitempty"`
}

// EgressRule contains all rule types which can be applied at egress, i.e.
// network traffic that originates inside the endpoint and exits the endpoint
// selected by the endpointSelector.
//
// - All members of this structure are optional. If omitted or empty, the
//   member will have no effect on the rule.
type EgressRule struct {
	// ToIdentities is a list of endpoints identified by an identitySelector to
	// which the endpoints subject to the rule are allowed to communicate.
	//
	// Example:
	// Any endpoint with the label "role=frontend" can communicate with any
	// endpoint carrying the label "role=backend".
	//
	// +optional
	ToIdentities *IdentityRule `json:"toIdentities,omitempty"`

	// ToRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be able to connect to other
	// endpoints. These additional constraints do not by themselves grant access
	// privileges and must always be accompanied with at least one matching
	// ToIdentities.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires any endpoint to which it
	// communicates to also carry the label "team=A".
	//
	// +optional
	ToRequires *IdentityRequirement `json:"toRequires,omitempty"`

	// ToCIDRs is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections. Only connections destined for
	// outside of the cluster and not targeting the host will be subject
	// to CIDR rules. This will match on the destination IP address of
	// outgoing connections.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24
	//
	// +optional
	ToCIDRs *CIDRRule `json:"toCIDR,omitempty"`

	// ToEntities is a list of special entities to which the endpoint subject
	// to the rule is allowed to initiate connections. Supported entities are
	// `world` and `host`
	//
	// +optional
	ToEntities *EntityRule `json:"toEntities,omitempty"`

	// ToServices is a list of services to which the endpoint subject
	// to the rule is allowed to initiate connections.
	//
	// Example:
	// Any endpoint with the label "app=backend-app" is allowed to
	// initiate connections to all cidrs backing the "external-service" service
	// + optional
	ToServices *ServiceRule `json:"toServices,omitempty"`
}

// IdentityRule is a rule that specifies an identitySelector in a form of
// matchLabels and matchExpressions that are allowed to communicate. If toPorts
// is specified the traffic will be filtered accordingly the given PortRules.
type IdentityRule struct {
	// IdentitySelector is the selector to or from which the traffic will be
	// allowed.
	IdentitySelector IdentitySelector `json:"identitySelector"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol on which the endpoint subject to the rule is allowed to
	// receive connections. If empty, all ports will be allowed.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp.
	//
	// +optional
	ToPorts *PortRule `json:"toPorts,omitempty"`
}

// IdentityRequirement is a list of additional constraints which must be met
// in order for the selected endpoints to be reachable. These additional
// constraints do no by itself grant access privileges and must always be
// accompanied with at least one matching FromEndpoints.
type IdentityRequirement struct {
	// IdentitySelector is the selector to or from which the traffic will be
	// allowed.
	IdentitySelector []IdentitySelector `json:"anyOf"`
}

// CIDRRule is a rule that specifies a CIDR prefix to/from which outside
// communication is allowed, along with an optional list of subnets within that
// CIDR prefix to/from which outside communication is not allowed.
type CIDRRule struct {
	// CIDR is a CIDR prefix / IP Block.
	CIDR []CIDR `json:"anyOf"`

	// ExceptCIDRs is a list of IP blocks which the endpoint subject to the rule
	// is not allowed to initiate connections to. These CIDR prefixes should be
	// contained within Cidr. These exceptions are only applied to the CIDR in
	// this CIDRRule, and do not apply to any other CIDR prefixes in any other
	// CIDRRules.
	//
	// +optional
	ExceptCIDRs []CIDR `json:"except,omitempty"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol on which the endpoint subject to the rule is allowed to
	// receive connections. If empty, all ports will be allowed.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp from IPs in CIDR prefix 10.0.0.0/8.
	//
	// +optional
	ToPorts *PortRule `json:"toPorts,omitempty"`

	// Generated indicates whether the rule was generated based on other rules
	// or provided by the user.
	Generated bool `json:"-"`
}

// EntityRule is a rule that specifies a list of entities to/from which
// communication is allowed.
type EntityRule struct {
	// Entities is a list of special entities from which the endpoint subject to
	// the rule is allowed to receive connections.
	Entities []Entity `json:"anyOf"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// receive connections on. If empty, all ports will be allowed.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp from "world".
	//
	// +optional
	ToPorts *PortRule `json:"toPorts,omitempty"`
}

// K8sServiceNamespace is an abstraction for the k8s service + namespace types.
type K8sServiceNamespace struct {
	ServiceName string `json:"serviceName,omitempty"`
	Namespace   string `json:"serviceNamespace,omitempty"`
}

// K8sServiceSelectorNamespace wraps service selector with namespace
type K8sServiceSelectorNamespace struct {
	Selector  ServiceSelector `json:"serviceSelector"`
	Namespace string          `json:"namespace,omitempty"`
}

// ServiceRule is a rule that allows to select a service by its namespace
// and name, or by a label selector.
type ServiceRule struct {
	// K8sServiceSelector selects services by Kubernetes labels and namespace.
	//
	// +optional
	K8sServiceSelector *K8sServiceSelectorNamespace `json:"k8sServiceSelector,omitempty"`

	// K8sService selects a service by a name and namespace pair.
	//
	// +optional
	K8sService *K8sServiceNamespace `json:"k8sService,omitempty"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// receive connections on. If empty, all ports will be allowed.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp from the service "frontend" in namespace
	// "qa".
	//
	// +optional
	ToPorts *PortRule `json:"toPorts,omitempty"`
}

// PortProtocol specifies a Layer 4 port with an optional transport protocol.
type PortProtocol struct {
	// Port is an L4 port number. For now the string will be strictly
	// parsed as a single uint16. In the future, this field may support
	// ranges in the form "1024-2048
	Port string `json:"port"`

	// Protocol is the Layer 4 protocol. If omitted or empty, any protocol
	// matches. Accepted values: "TCP", "UDP", ""/"ANY"
	//
	// Matching on ICMP is not supported.
	//
	// +optional
	Protocol L4Proto `json:"protocol,omitempty"`
}

// PortRule is a list of ports/protocol combinations with optional Layer 7
// rules which must be met.
type PortRule struct {
	// Ports is a list of Layer 4 port/protocol pairs.
	//
	// If omitted or empty, but with RedirectPort set, then all ports of the
	// endpoint subject to either the ingress or egress rule are being
	// redirected to the proxy.
	//
	// +optional
	Ports []PortProtocol `json:"anyOf,omitempty"`

	// Rules is a list of additional port level rules which must be met in
	// order for the PortRule to allow traffic. If omitted or empty,
	// no Layer 7 rules are enforced.
	//
	// +optional
	Rules *L7Rules `json:"rules,omitempty"`
}

// IsWildcard returns true if PortRule is nil or PortRule.Ports slice is empty.
func (pr *PortRule) IsWildcard() bool {
	return pr == nil || len(pr.Ports) == 0
}

// L7Rules is a union of port-level rule types. Mixing of different port-level
// rule types is not allowed; exactly one of the following must be set.
// If none are specified, then no additional port-level rules are applied.
type L7Rules struct {
	// HTTP specific rules.
	//
	// +optional
	HTTP []PortRuleHTTP `json:"http,omitempty"`

	// Kafka-specific rules.
	//
	// +optional
	Kafka []PortRuleKafka `json:"kafka,omitempty"`
}

// PortRules is a slice of PortRule.
type PortRules []PortRule

// ServiceSelector is a label selector for Kubernetes services.
type ServiceSelector IdentitySelector

// Entity specifies the class of receiver/sender endpoints that do not have
// individual identities. Entities are used to describe "outside of cluster",
// "host", etc.
type Entity string

const (
	// EntityWorld is an entity that represents traffic external to an
	// endpoint's cluster.
	EntityWorld Entity = "world"
	// EntityHost is an entity that represents traffic within the endpoint's
	// host.
	EntityHost Entity = "host"
	// EntityAll is an entity that represents all traffic.
	EntityAll Entity = "all"
)

// EntitySelectorMapping maps special entity names that come in policies to
// selectors.
var EntitySelectorMapping = map[Entity]IdentitySelector{
	EntityWorld: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameWorld,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
	EntityHost: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameHost,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
	EntityAll: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameAll,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
}

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
type CIDR string

// CIDRMatchAll is a []CIDR that matches everything
var CIDRMatchAll = NewWildcardCIDR()

// NewWildcardCIDR returns a CIDR that matches on all IPs.
func NewWildcardCIDR() []CIDR {
	return []CIDR{CIDR("0.0.0.0/0"), CIDR("::/0")}
}

// L4Proto is a Layer 4 protocol name.
type L4Proto string

const (
	ProtoTCP L4Proto = "TCP"
	ProtoUDP L4Proto = "UDP"
	ProtoAny L4Proto = "ANY"
)
