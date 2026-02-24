// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
)

// PortRuleL7 is a list of key-value pairs interpreted by a L7 protocol as
// protocol constraints. All fields are optional, if all fields are empty or
// missing, the rule does not have any effect.
type PortRuleL7 map[string]string

// Sanitize sanitizes key-value pair rules. It makes sure keys are present.
func (rule *PortRuleL7) Sanitize() error {
	for k := range *rule {
		if k == "" {
			return fmt.Errorf("Empty key not allowed")
		}
	}
	return nil
}
