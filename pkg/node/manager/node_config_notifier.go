// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"errors"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/config"
)

// NodeConfigNotifier is used to notify subscribers about changes in the local node configuration.
// Handlers must be subscribed during hive construction, before the lifecycle starts.
type NodeConfigNotifier struct {
	handlers []config.ChangeHandler
	started  bool
}

func newNodeConfigNotifier(lifecycle cell.Lifecycle) *NodeConfigNotifier {
	ncn := &NodeConfigNotifier{
		handlers: make([]config.ChangeHandler, 0),
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			ncn.started = true
			return nil
		},
	})

	return ncn
}

func (n *NodeConfigNotifier) Subscribe(handler config.ChangeHandler) {
	if n.started {
		panic("Cannot subscribe to NodeConfigChangeHandler after lifecycle has started")
	}

	n.handlers = append(n.handlers, handler)
}

func (n *NodeConfigNotifier) Notify(nodeConfig config.Config) error {
	var errs error
	for _, handler := range n.handlers {
		errs = errors.Join(errs, handler.NodeConfigurationChanged(nodeConfig))
	}
	return errs
}
