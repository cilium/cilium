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
// labels contained in the endpointSelector
//
// Each rule is split into an ingress section which contains all rules
// applicable at ingress, and an egress section applicable at egress. For rule
// types such as `L4Rule` and `CIDR` which can be applied at both ingress and
// egress, both ingress and egress side have to either specifically allow the
// connection or one side has to be omitted.
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

type IngressRule struct {
	FromIdentities *IdentityRule `json:"fromIdentities,omitempty"`

	FromRequires *IdentityRequirement `json:"fromRequires,omitempty"`

	FromCIDRs *CIDRRule `json:"fromCIDR,omitempty"`

	FromEntities *EntityRule `json:"fromEntities,omitempty"`
}

type EgressRule struct {
	ToIdentities *IdentityRule `json:"toIdentities,omitempty"`

	ToRequires *IdentityRequirement `json:"toRequires,omitempty"`

	ToCIDRs *CIDRRule `json:"toCIDR,omitempty"`

	ToEntities *EntityRule `json:"toEntities,omitempty"`

	ToServices *ServiceRule `json:"toServices,omitempty"`
}

type IdentityRule struct {
	IdentitySelector IdentitySelector `json:"identitySelector"`
	ToPorts          *PortRule        `json:"toPorts,omitempty"`
}

type IdentityRequirement struct {
	IdentitySelector []IdentitySelector `json:"anyOf"`
}

type CIDRRule struct {
	CIDR        []CIDR    `json:"anyOf"`
	ExceptCIDRs []CIDR    `json:"except,omitempty"`
	Generated   bool      `json:"-"`
	ToPorts     *PortRule `json:"toPorts,omitempty"`
}

type EntityRule struct {
	Entities []Entity  `json:"anyOf"`
	ToPorts  *PortRule `json:"toPorts,omitempty"`
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

type ServiceRule struct {
	// K8sServiceSelector selects services by k8s labels and namespace
	K8sServiceSelector *K8sServiceSelectorNamespace `json:"k8sServiceSelector,omitempty"`
	// K8sService selects service by name and namespace pair
	K8sService *K8sServiceNamespace `json:"k8sService,omitempty"`
	ToPorts    *PortRule            `json:"toPorts,omitempty"`
}

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
	Ports []PortProtocol `json:"anyOf,omitempty"`

	// Rules is a list of additional port level rules which must be met in
	// order for the PortRule to allow the traffic. If omitted or empty,
	// no layer 7 rules are enforced.
	//
	// +optional
	Rules *L7Rules `json:"rules,omitempty"`
}

// IsWildcard returns true if PortRule is nil or PortRule.Ports slice is empty.
func (pr *PortRule) IsWildcard() bool {
	return pr == nil || len(pr.Ports) == 0
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
}

type PortRules []PortRule

// ServiceSelector is a label selector for k8s services
type ServiceSelector IdentitySelector

// Entities specifies the class of receiver/sender endpoints that do not have individual identities.
// Entities are used to describe "outside of cluster", "host", etc.
type Entity string

const (
	// EntityWorld is an entity that represents traffic external to endpoint's cluster
	EntityWorld Entity = "world"
	// EntityHost is an entity that represents traffic within endpoint host
	EntityHost Entity = "host"
	// EntityAll is an entity that represents all traffic
	EntityAll Entity = "all"
)

// EntitySelectorMapping maps special entity names that come in policies to selectors
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

// L4Proto is a layer 4 protocol name
type L4Proto string

const (
	ProtoTCP L4Proto = "TCP"
	ProtoUDP L4Proto = "UDP"
	ProtoAny L4Proto = "ANY"
)
