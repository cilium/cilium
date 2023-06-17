// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"strings"
)

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
		len(h.Headers) != len(o.Headers) ||
		len(h.HeaderMatches) != len(o.HeaderMatches) {
		return false
	}

	for i, value := range h.Headers {
		if o.Headers[i] != value {
			return false
		}
	}

	for i, value := range h.HeaderMatches {
		if !o.HeaderMatches[i].Equal(value) {
			return false
		}
	}
	return true
}

// Equal returns true if both Secrets are equal
func (a *Secret) Equal(b *Secret) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// Equal returns true if both HeaderMatches are equal
func (h *HeaderMatch) Equal(o *HeaderMatch) bool {
	if h.Mismatch != o.Mismatch ||
		h.Name != o.Name ||
		h.Value != o.Value ||
		!h.Secret.Equal(o.Secret) {
		return false
	}
	return true
}

// Exists returns true if the DNS rule already exists in the list of rules
func (d *PortRuleDNS) Exists(rules L7Rules) bool {
	for _, existingRule := range rules.DNS {
		if d.Equal(existingRule) {
			return true
		}
	}

	return false
}

// Exists returns true if the L7 rule already exists in the list of rules
func (h *PortRuleL7) Exists(rules L7Rules) bool {
	for _, existingRule := range rules.L7 {
		if h.Equal(existingRule) {
			return true
		}
	}

	return false
}

// Equal returns true if both rules are equal
func (d *PortRuleDNS) Equal(o PortRuleDNS) bool {
	return d != nil && d.MatchName == o.MatchName && d.MatchPattern == o.MatchPattern
}

// Equal returns true if both L7 rules are equal
func (h *PortRuleL7) Equal(o PortRuleL7) bool {
	if len(*h) != len(o) {
		return false
	}
	for k, v := range *h {
		if v2, ok := o[k]; !ok || v2 != v {
			return false
		}
	}
	return true
}

// Validate returns an error if the layer 4 protocol is not valid
func (l4 L4Proto) Validate() error {
	switch l4 {
	case ProtoAny, ProtoTCP, ProtoUDP, ProtoSCTP:
	default:
		return fmt.Errorf("invalid protocol %q, must be { tcp | udp | sctp | any }", l4)
	}

	return nil
}

// ParseL4Proto parses a string as layer 4 protocol
func ParseL4Proto(proto string) (L4Proto, error) {
	if proto == "" {
		return ProtoAny, nil
	}

	p := L4Proto(strings.ToUpper(proto))
	return p, p.Validate()
}

// ResourceQualifiedName returns the qualified name of an Envoy resource,
// prepending CEC namespace and CEC name to the resource name and using
// '/' as a separator.
//
// If resourceName already has a slash, it must be of the form 'namespace/name', where namespace
// usually is equal to 'namespace'. This also applies for clusterwide resources for which
// 'namespace' is empty.
//
// If 'resourceName' has no slash, it will be prepended with 'namespace/cecName' so that the
// full name passed to Envoy is 'namespace/cecName/resourceName'. This makes non-qualified resource
// names and resource name references local to the given namespace and CiliumEnvoyConfig CRD.
//
// if 'forceNamespace' is 'true' then resourceName is always prepended with "namespace/cecName/",
// even it it already has backslashes, unless the first component of the name is equal to
// 'namespace'.
//
// As a special case pass through an empty resourceName without qualification so that unnamed
// resources do not become named. This is important to not transform an invalid Envoy configuration
// to a valid one with a fake name.

type Option int

const (
	ForceNamespace Option = iota
)

func ResourceQualifiedName(namespace, cecName, resourceName string, options ...Option) string {
	forceNamespace := false
	for _, option := range options {
		switch option {
		case ForceNamespace:
			forceNamespace = true
		}
	}

	idx := strings.IndexRune(resourceName, '/')
	if resourceName == "" || idx >= 0 && (!forceNamespace || (idx == len(namespace) && strings.HasPrefix(resourceName, namespace))) {
		return resourceName
	}

	var sb strings.Builder

	sb.WriteString(namespace)
	sb.WriteRune('/')
	sb.WriteString(cecName)
	sb.WriteRune('/')
	sb.WriteString(resourceName)

	return sb.String()
}
