// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"errors"

	"github.com/cilium/hive/cell"
)

// NodeConfigNotifierCell provides the local node configuration notifier.
var NodeConfigNotifierCell = cell.Module(
	"node-config-notifier",
	"Notifies datapath components about local node configuration changes",
	cell.Provide(newNodeConfigNotifier),
)

// NodeConfigNotifier notifies subscribers about changes in the local node
// configuration. Handlers must subscribe during Hive construction.
type NodeConfigNotifier struct {
	handlers []ChangeHandler
	started  bool
}

func newNodeConfigNotifier(lifecycle cell.Lifecycle) *NodeConfigNotifier {
	n := &NodeConfigNotifier{handlers: []ChangeHandler{}}
	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			n.started = true
			return nil
		},
	})
	return n
}

// Subscribe registers a configuration change handler.
func (n *NodeConfigNotifier) Subscribe(handler ChangeHandler) {
	if n.started {
		panic("Cannot subscribe to NodeConfigChangeHandler after lifecycle has started")
	}
	n.handlers = append(n.handlers, handler)
}

// Notify invokes all registered configuration change handlers.
func (n *NodeConfigNotifier) Notify(nodeConfig Config) error {
	var errs error
	for _, handler := range n.handlers {
		errs = errors.Join(errs, handler.NodeConfigurationChanged(nodeConfig))
	}
	return errs
}
