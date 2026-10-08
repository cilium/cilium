// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"github.com/cilium/hive/cell"

	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// NodePolicy controls policy decisions made while reconciling Linux node
// datapath state. Policy overrides must be installed during Hive construction,
// before the Linux node reconciler starts.
type NodePolicy struct {
	enableEncapsulation func(*nodeTypes.Node) bool
	sealed              bool
}

// NewNodePolicy constructs the Linux node reconciliation policy and seals it
// when the Hive lifecycle starts.
func NewNodePolicy(lifecycle cell.Lifecycle) *NodePolicy {
	p := newNodePolicy()
	lifecycle.Append(p)
	return p
}

func newNodePolicy() *NodePolicy { return &NodePolicy{} }

// SetEnableEncapsulation overrides the per-node encapsulation decision.
func (p *NodePolicy) SetEnableEncapsulation(fn func(*nodeTypes.Node) bool) {
	if p.sealed {
		panic("Linux node policy cannot be changed after startup")
	}
	p.enableEncapsulation = fn
}

// EnableEncapsulation returns the per-node encapsulation decision. The caller
// supplies the current datapath configuration as the default because it may
// change after the policy has been constructed.
func (p *NodePolicy) EnableEncapsulation(n *nodeTypes.Node, defaultValue bool) bool {
	if p.enableEncapsulation != nil {
		return p.enableEncapsulation(n)
	}
	return defaultValue
}

// Start implements cell.HookInterface.
func (p *NodePolicy) Start(cell.HookContext) error {
	p.sealed = true
	return nil
}

// Stop implements cell.HookInterface.
func (*NodePolicy) Stop(cell.HookContext) error { return nil }
