// Copyright 2016-2017 Authors of Cilium
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

// Decision is a reachability policy decision
type Decision byte

const (
	// Undecided means that we have not come to a decision yet
	Undecided Decision = iota
	// Allowed means that reachability is allowed
	Allowed
	// Denied means that reachability is denied
	Denied
)

var (
	decisionToString = map[Decision]string{
		Undecided: "undecided",
		Allowed:   "allowed",
		Denied:    "denied",
	}
	stringToDecision = map[string]Decision{
		"undecided": Undecided,
		"allowed":   Allowed,
		"denied":    Denied,
	}
)

// String returns the decision in human readable format
func (d Decision) String() string {
	if v, exists := decisionToString[d]; exists {
		return v
	}
	return ""
}

// UnmarshalJSON parses a JSON formatted buffer and returns a decision
func (d *Decision) UnmarshalJSON(b []byte) error {
	if d == nil {
		d = new(Decision)
	}
	if len(b) <= len(`""`) {
		return fmt.Errorf("invalid decision '%s'", string(b))
	}
	if v, exists := stringToDecision[string(b[1:len(b)-1])]; exists {
		*d = v
		return nil
	}

	return fmt.Errorf("unknown '%s' decision", string(b))
}

// MarshalJSON returns the decision as JSON formatted buffer
func (d Decision) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d)), nil
}
