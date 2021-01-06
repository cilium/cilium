// Copyright 2018 Authors of Cilium
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
