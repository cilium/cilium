// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defines

import (
	"fmt"

	"github.com/cilium/cilium/pkg/hive/cell"
)

// Map is the type containing the key-value pairs representing extra define
// directives for datapath node configuration.
type Map map[string]string

func (m Map) Merge(other Map) error {
	for key, value := range other {
		if _, ok := m[key]; ok {
			return fmt.Errorf("extra node define overwrites key %q", key)
		}

		m[key] = value
	}
	return nil
}

// NodeOut allows injecting configuration into the datapath.
type NodeOut struct {
	cell.Out
	NodeDefines Map `group:"header-node-defines"`
}

// Fn is a function returning the key-value pairs representing extra define
// directives for datapath node configuration.
type Fn func() (Map, error)

// NodeFnOut allows injecting configuration into the datapath
// by invoking a callback.
//
// Prefer using [NodeOut] if possible since it has a valid zero value.
type NodeFnOut struct {
	cell.Out
	// Fn must not be nil.
	Fn `group:"header-node-define-fns"`
}

// NewNodeFnOut wraps a function returning the key-value pairs representing
// extra define directives for datapath node configuration, so that it can be
// provided through the hive framework.
func NewNodeFnOut(fn Fn) NodeFnOut {
	return NodeFnOut{Fn: fn}
}
