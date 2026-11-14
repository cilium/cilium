// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package qos resolves the CiliumQoSMechanism, CiliumQoSClass and
// CiliumQoSPolicy resources into the concrete markings the datapath applies to
// a flow.
package qos

import (
	"fmt"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// Class is a CiliumQoSClass whose mechanism reference has been resolved
// against the declared CiliumQoSMechanism resources.
type Class struct {
	// Name is the name of the CiliumQoSClass.
	Name string

	// Mechanism is the type of the mechanism the class configures, taken
	// from the CiliumQoSMechanism it references.
	Mechanism v2alpha1.QoSMechanismType

	// Priority orders classes of the same mechanism that are selected by
	// equally specific rules. Higher wins.
	Priority int32

	// DSCP is the codepoint to mark with, set when Mechanism is DSCP.
	DSCP uint8

	// NodePriority is the node-local scheduling class, set when Mechanism is
	// NodePriority.
	NodePriority v2alpha1.NodePriorityLevel
}

// ResolveClass resolves a CiliumQoSClass against the mechanisms declared in
// the cluster, keyed by name.
//
// It fails if the referenced mechanism has not been declared, or if the class
// configures a mechanism other than the one it references: a class is only
// meaningful once both halves agree.
func ResolveClass(class *v2alpha1.CiliumQoSClass, mechanisms map[string]*v2alpha1.CiliumQoSMechanism) (Class, error) {
	mechanismName := class.Spec.MechanismRef.Name

	mechanism, ok := mechanisms[mechanismName]
	if !ok {
		return Class{}, fmt.Errorf("class %q references undeclared mechanism %q", class.Name, mechanismName)
	}

	out := Class{
		Name:      class.Name,
		Mechanism: mechanism.Spec.Type,
		Priority:  class.Spec.Priority,
	}

	params := class.Spec.Parameters
	switch mechanism.Spec.Type {
	case v2alpha1.QoSMechanismDSCP:
		if params.DSCP == nil {
			return Class{}, fmt.Errorf("class %q references mechanism %q of type %s but does not set parameters.dscp",
				class.Name, mechanismName, mechanism.Spec.Type)
		}
		if params.DSCP.Value > MaxDSCP {
			return Class{}, fmt.Errorf("class %q sets DSCP value %d, out of the 0-%d range",
				class.Name, params.DSCP.Value, MaxDSCP)
		}
		out.DSCP = params.DSCP.Value
	case v2alpha1.QoSMechanismNodePriority:
		if params.NodePriority == nil {
			return Class{}, fmt.Errorf("class %q references mechanism %q of type %s but does not set parameters.nodePriority",
				class.Name, mechanismName, mechanism.Spec.Type)
		}
		out.NodePriority = params.NodePriority.Priority
	default:
		return Class{}, fmt.Errorf("class %q references mechanism %q of unknown type %q",
			class.Name, mechanismName, mechanism.Spec.Type)
	}

	return out, nil
}

// MaxDSCP is the largest DSCP codepoint, the field being 6 bits wide.
const MaxDSCP = 63

// Marking is the set of QoS actions that apply to a flow, at most one per
// mechanism. A nil field means the mechanism does not apply and the datapath
// leaves the corresponding packet field alone.
type Marking struct {
	DSCP         *uint8
	NodePriority *v2alpha1.NodePriorityLevel
}

// IsZero reports whether no mechanism applies.
func (m Marking) IsZero() bool {
	return m.DSCP == nil && m.NodePriority == nil
}
