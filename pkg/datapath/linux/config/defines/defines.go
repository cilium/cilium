// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defines

import "github.com/cilium/cilium/pkg/hive/cell"

// Map is the type containing the key-value pairs representing extra define
// directives for datapath node configuration.
type Map map[string]string

// Fn is a function returning the key-value pairs representing extra define
// directives for datapath node configuration.
type Fn func() (Map, error)

type NodeFnOut struct {
	cell.Out
	Fn `group:"header-node-defines"`
}

// NewNodeFnOut wraps a function returning the key-value pairs representing
// extra define directives for datapath node configuration, so that it can be
// provided through the hive framework.
func NewNodeFnOut(fn Fn) NodeFnOut {
	return NodeFnOut{Fn: fn}
}
