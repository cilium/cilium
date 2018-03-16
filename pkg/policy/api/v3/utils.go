// Copyright 2017-2018 Authors of Cilium
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
	"fmt"
	"strings"
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

// Equal returns true if both rules are equal
func (k *PortRuleKafka) Equal(o PortRuleKafka) bool {
	return k.APIVersion == o.APIVersion && k.APIKey == o.APIKey &&
		k.Topic == o.Topic && k.ClientID == o.ClientID && k.Role == o.Role
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
