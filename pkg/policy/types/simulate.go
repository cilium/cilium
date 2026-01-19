// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Some types for simulating and looking up policy. These are used in multiple packages.

// Flow is a possible traffic to look up from the policy engine.
type Flow struct {
	From, To *identity.Identity
	Proto    u8proto.U8proto
	Dport    uint16

	// Any known named ports
	NamedPortsTCP map[string]uint16
	NamedPortsUDP map[string]uint16
}

// LookupResult is the policy verdict for a given flow
type LookupResult struct {
	Egress  Decision
	Ingress Decision
}

type Decision uint8

const (
	DecisionUndecided Decision = iota
	DecisionAllowed
	DecisionDenied
)

func (d Decision) String() string {
	switch d {
	case DecisionUndecided:
		return "undecided"
	case DecisionAllowed:
		return "allowed"
	case DecisionDenied:
		return "denied"
	}
	return ""
}

func (v LookupResult) Allowed() bool {
	return v.Egress != DecisionDenied && v.Ingress != DecisionDenied
}

func (v LookupResult) String() string {
	return fmt.Sprintf("egress: %s, ingress %s", v.Egress, v.Ingress)
}
