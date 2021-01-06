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
	case ProtoAny, ProtoTCP, ProtoUDP:
	default:
		return fmt.Errorf("invalid protocol %q, must be { tcp | udp | any }", l4)
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
