// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package subscriber

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
)

var _ Node = (*NodeChain)(nil)

// Node is implemented by event handlers responding to K8s Node events.
type Node interface {
	OnAddNode(*v1.Node) error
	OnUpdateNode(oldObj, newObj *v1.Node) error
	OnDeleteNode(*v1.Node) error
}

// NodeChain holds the subsciber.Node implementations that are notified when reacting
// to K8s Node resource / object changes in the K8s watchers.
//
// NodeChain itself is an implementation of subscriber.Node with an additional
// Register method for attaching children subscribers to the chain.
type NodeChain struct {
	list

	subs []Node
}

// NewNodeChain creates a NodeChain ready for it's
// Register method to be called.
func NewNodeChain() *NodeChain {
	return &NodeChain{}
}

// Register registers NodeHandler as a subscriber for reacting to Node objects
// into the list.
func (l *NodeChain) Register(s Node) {
	l.Lock()
	l.subs = append(l.subs, s)
	l.Unlock()
}

// NotifyAdd notifies all the subscribers of an add event to a service.
func (l *NodeChain) OnAddNode(node *v1.Node) error {
	l.RLock()
	defer l.RUnlock()
	errs := make([]error, 0, len(l.subs))
	for _, s := range l.subs {
		if err := s.OnAddNode(node); err != nil {
			errs = append(errs, err)
		}
	}
	return fmt.Errorf("Errors: %v", errs)
}

// NotifyUpdate notifies all the subscribers of an update event to a service.
func (l *NodeChain) OnUpdateNode(oldNode, newNode *v1.Node) error {
	l.RLock()
	defer l.RUnlock()
	errs := make([]error, 0, len(l.subs))
	for _, s := range l.subs {
		if err := s.OnUpdateNode(oldNode, newNode); err != nil {
			errs = append(errs, err)
		}
	}
	return fmt.Errorf("Errors: %v", errs)
}

// NotifyDelete notifies all the subscribers of an update event to a service.
func (l *NodeChain) OnDeleteNode(node *v1.Node) error {
	l.RLock()
	defer l.RUnlock()
	errs := make([]error, 0, len(l.subs))
	for _, s := range l.subs {
		if err := s.OnDeleteNode(node); err != nil {
			errs = append(errs, err)
		}
	}
	return fmt.Errorf("Errors: %v", errs)
}
