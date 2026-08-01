// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library

import (
	"github.com/google/cel-go/cel"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

const (
	// FlowVarName is the CEL variable name bound to the Hubble flow object
	// in FlowFilter expressions.
	FlowVarName = "_flow"
)

// FlowFilter returns a cel.EnvOption that configures the FlowFilter CEL
// environment for evaluating boolean expressions against Hubble flows.
// Expressions receive the flow as the variable named FlowVarName ("_flow").
//
// Unqualified protobuf enum names (e.g. Verdict.FORWARDED) are resolved in
// the "flow" package namespace via cel.Container("flow").
func FlowFilter() cel.EnvOption {
	return cel.Lib(&flowFilterLib{})
}

type flowFilterLib struct{}

func (*flowFilterLib) LibraryName() string {
	return "cilium.flow"
}

func (*flowFilterLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// Resolve unqualified type names (e.g. Verdict.FORWARDED) within
		// the "flow" protobuf package namespace.
		cel.Container("flow"),
		// Register all flow protobuf types so field access is type-checked.
		cel.Types(&flowpb.Flow{}),
		// Declare the _flow variable for use in filter expressions.
		cel.Variable(FlowVarName, cel.ObjectType("flow.Flow")),
	}
}

func (*flowFilterLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
