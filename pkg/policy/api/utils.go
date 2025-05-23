// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// Exists returns true if the HTTP rule already exists in the list of rules
func (h *PortRuleHTTP) Exists(rules L7Rules) bool {
	return slices.ContainsFunc(rules.HTTP, h.Equal)
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

func (h PortRuleHTTP) Compare(o PortRuleHTTP) int {
	if n := strings.Compare(h.Path, o.Path); n != 0 {
		return n
	}
	if n := strings.Compare(h.Method, o.Method); n != 0 {
		return n
	}
	if n := strings.Compare(h.Host, o.Host); n != 0 {
		return n
	}

	if len(h.Headers) != len(o.Headers) {
		return len(h.Headers) - len(o.Headers)
	}
	for i := range len(h.Headers) {
		if n := strings.Compare(h.Headers[i], o.Headers[i]); n != 0 {
			return n
		}
	}

	if len(h.HeaderMatches) != len(o.HeaderMatches) {
		return len(h.HeaderMatches) - len(o.HeaderMatches)
	}
	for i, value := range h.HeaderMatches {
		if n := value.Compare(o.HeaderMatches[i]); n != 0 {
			return n
		}
	}

	return 0
}

// Equal returns true if both Secrets are equal
func (a *Secret) Equal(b *Secret) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func (a *Secret) Compare(b *Secret) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	if n := strings.Compare(a.Namespace, b.Namespace); n != 0 {
		return n
	}
	if n := strings.Compare(a.Name, b.Name); n != 0 {
		return n
	}
	return 0
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

func (h *HeaderMatch) Compare(o *HeaderMatch) int {
	if h == nil && o == nil {
		return 0
	}
	if h == nil {
		return -1
	}
	if o == nil {
		return 1
	}
	if n := strings.Compare(h.Name, o.Name); n != 0 {
		return n
	}
	if n := strings.Compare(h.Value, o.Value); n != 0 {
		return n
	}
	if n := strings.Compare(string(h.Mismatch), string(o.Mismatch)); n != 0 {
		return n
	}
	return h.Secret.Compare(o.Secret)
}

// Exists returns true if the DNS rule already exists in the list of rules
func (d *PortRuleDNS) Exists(rules L7Rules) bool {
	return slices.ContainsFunc(rules.DNS, d.Equal)
}

// Exists returns true if the L7 rule already exists in the list of rules
func (h *PortRuleL7) Exists(rules L7Rules) bool {
	return slices.ContainsFunc(rules.L7, h.Equal)
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

func ResourceQualifiedName(namespace, cecName, resourceName string, options ...Option) (name string, updated bool) {
	forceNamespace := false
	for _, option := range options {
		switch option {
		case ForceNamespace:
			forceNamespace = true
		}
	}

	idx := strings.IndexRune(resourceName, '/')
	if resourceName == "" || idx >= 0 && (!forceNamespace || (idx == len(namespace) && strings.HasPrefix(resourceName, namespace))) {
		return resourceName, false
	}

	var sb strings.Builder

	sb.WriteString(namespace)
	sb.WriteRune('/')
	sb.WriteString(cecName)
	sb.WriteRune('/')
	sb.WriteString(resourceName)

	return sb.String(), true
}

// ParseQualifiedName returns the namespace, name, and the resource name of a name qualified with ResourceQualifiedName()
func ParseQualifiedName(qualifiedName string) (namespace, name, resourceName string) {
	parts := strings.SplitN(qualifiedName, "/", 3)
	if len(parts) < 3 {
		return "", "", qualifiedName
	}
	return parts[0], parts[1], parts[2]
}

// ExtractCidrSet abstracts away some of the logic from the CreateDerivative methods
func ExtractCidrSet(ctx context.Context, groups []Groups) ([]CIDRRule, error) {
	var cidrSet []CIDRRule
	for _, group := range groups {
		c, err := group.GetCidrSet(ctx)
		if err != nil {
			return cidrSet, err
		}
		if len(c) > 0 {
			cidrSet = append(cidrSet, c...)
		}
	}
	return cidrSet, nil
}
