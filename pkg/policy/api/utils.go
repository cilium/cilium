// Copyright 2017-2020 Authors of Cilium
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
		if h.DeepEqual(&existingRule) {
			return true
		}
	}

	return false
}

// DeepEqual returns true if both Secrets are equal
func (a *Secret) DeepEqual(b *Secret) bool {
	if a == nil {
		return b == nil
	}
	return a.deepEqual(b)
}

// Exists returns true if the DNS rule already exists in the list of rules
func (d *PortRuleDNS) Exists(rules L7Rules) bool {
	for _, existingRule := range rules.DNS {
		if d.DeepEqual(&existingRule) {
			return true
		}
	}

	return false
}

// Exists returns true if the L7 rule already exists in the list of rules
func (h *PortRuleL7) Exists(rules L7Rules) bool {
	for _, existingRule := range rules.L7 {
		if h.DeepEqual(&existingRule) {
			return true
		}
	}

	return false
}

// DeepEqual returns true if both rules are equal
func (d *PortRuleDNS) DeepEqual(o *PortRuleDNS) bool {
	if d == nil {
		return o == nil
	}
	return d.deepEqual(o)
}

// DeepEqual returns true if both L7 rules are equal
func (h *PortRuleL7) DeepEqual(o *PortRuleL7) bool {
	if h == nil {
		return o == nil || *o == nil
	}
	return h.deepEqual(o)
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
