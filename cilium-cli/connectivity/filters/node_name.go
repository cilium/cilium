// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type nodeNameFilter struct {
	name string
}

// NodeName matches flows observed on the given node. It accepts both a bare
// Kubernetes node name and Hubble's cluster-qualified node name.
func NodeName(name string) FlowFilterImplementation {
	return &nodeNameFilter{name: name}
}

func (f *nodeNameFilter) Match(flow *flowpb.Flow, _ *FlowContext) bool {
	return flow.GetNodeName() == f.name || strings.HasSuffix(flow.GetNodeName(), "/"+f.name)
}

func (f *nodeNameFilter) String(_ *FlowContext) string {
	return "node-name(" + f.name + ")"
}
