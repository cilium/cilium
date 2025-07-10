// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"errors"

	"github.com/cilium/hive/cell"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

// NodeConfigNotifier is used to notify subscribers about changes in the local node configuration.
// Handlers must be subscribed during hive construction, before the lifecycle starts.
type NodeConfigNotifier struct {
	handlers []datapath.NodeConfigChangeHandler
	started  bool
}

func newNodeConfigNotifier(lifecycle cell.Lifecycle) *NodeConfigNotifier {
	ncn := &NodeConfigNotifier{
		handlers: make([]datapath.NodeConfigChangeHandler, 0),
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			ncn.started = true
			return nil
		},
	})

	return ncn
}

func (n *NodeConfigNotifier) Subscribe(handler datapath.NodeConfigChangeHandler) {
	if n.started {
		panic("Cannot subscribe to NodeConfigChangeHandler after lifecycle has started")
	}

	n.handlers = append(n.handlers, handler)
}

func (n *NodeConfigNotifier) Notify(nodeConfig datapath.LocalNodeConfiguration) error {
	var errs error
	for _, handler := range n.handlers {
		errs = errors.Join(errs, handler.NodeConfigurationChanged(nodeConfig))
	}
	return errs
}
