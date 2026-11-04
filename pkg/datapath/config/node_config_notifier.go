// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"errors"

	"github.com/cilium/hive/cell"
)

// NodeConfigNotifierCell provides notifications about local node configuration changes.
var NodeConfigNotifierCell = cell.Module(
	"node-config-notifier",
	"Provides local node configuration notifications",
	cell.Provide(newNodeConfigNotifier),
)

// NodeConfigNotifier is used to notify subscribers about changes in the local node configuration.
// Handlers must be subscribed during hive construction, before the lifecycle starts.
type NodeConfigNotifier struct {
	handlers []ChangeHandler
	started  bool
}

func newNodeConfigNotifier(lifecycle cell.Lifecycle) *NodeConfigNotifier {
	ncn := &NodeConfigNotifier{
		handlers: make([]ChangeHandler, 0),
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			ncn.started = true
			return nil
		},
	})

	return ncn
}

func (n *NodeConfigNotifier) Subscribe(handler ChangeHandler) {
	if n.started {
		panic("Cannot subscribe to NodeConfigChangeHandler after lifecycle has started")
	}

	n.handlers = append(n.handlers, handler)
}

func (n *NodeConfigNotifier) Notify(nodeConfig Config) error {
	var errs error
	for _, handler := range n.handlers {
		errs = errors.Join(errs, handler.NodeConfigurationChanged(nodeConfig))
	}
	return errs
}
