// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	s := d.String()
	// length of decision string plus two `"`
	b := make([]byte, len(s)+2)
	b[0] = '"'
	copy(b[1:], s)
	b[len(b)-1] = '"'
	return b, nil
}
