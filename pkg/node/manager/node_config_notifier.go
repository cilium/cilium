// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"errors"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

type NodeConfigNotifier struct {
	handlers []datapath.NodeConfigChangeHandler
}

func newNodeConfigNotifier() *NodeConfigNotifier {
	return &NodeConfigNotifier{
		handlers: make([]datapath.NodeConfigChangeHandler, 0),
	}
}

func (n *NodeConfigNotifier) Subscribe(handler datapath.NodeConfigChangeHandler) {
	n.handlers = append(n.handlers, handler)
}

func (n *NodeConfigNotifier) Unsubscribe(handler datapath.NodeConfigChangeHandler) {
	for i, h := range n.handlers {
		if h == handler {
			n.handlers = append(n.handlers[:i], n.handlers[i+1:]...)
			return
		}
	}
}

func (n *NodeConfigNotifier) Notify(nodeConfig datapath.LocalNodeConfiguration) error {
	var errs error
	for _, handler := range n.handlers {
		if err := handler.NodeConfigurationChanged(nodeConfig); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}
