// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subscriber

import (
	"fmt"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
)

var _ Node = (*NodeChain)(nil)

// Node is implemented by event handlers responding to K8s Node events.
type Node interface {
	OnAddNode(*slim_corev1.Node, *lock.StoppableWaitGroup) error
	OnUpdateNode(oldObj, newObj *slim_corev1.Node, swg *lock.StoppableWaitGroup) error
	OnDeleteNode(*slim_corev1.Node, *lock.StoppableWaitGroup) error
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
func (l *NodeChain) OnAddNode(node *slim_corev1.Node, swg *lock.StoppableWaitGroup) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnAddNode(node, swg); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// NotifyUpdate notifies all the subscribers of an update event to a service.
func (l *NodeChain) OnUpdateNode(oldNode, newNode *slim_corev1.Node,
	swg *lock.StoppableWaitGroup) error {

	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnUpdateNode(oldNode, newNode, swg); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// NotifyDelete notifies all the subscribers of an update event to a service.
func (l *NodeChain) OnDeleteNode(node *slim_corev1.Node, swg *lock.StoppableWaitGroup) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnDeleteNode(node, swg); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}
