// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subscriber

import (
	"fmt"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
)

var _ CiliumNode = (*CiliumNodeChain)(nil)

// CiliumNode is implemented by event handlers responding to CiliumNode events.
type CiliumNode interface {
	OnAddCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error
	OnUpdateCiliumNode(oldObj, newObj *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error
	OnDeleteCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error
}

// CiliumNodeChain holds the subsciber.CiliumNode implementations that are
// notified when reacting to CiliumNode resource / object changes in the K8s
// watchers.
//
// CiliumNodeChain itself is an implementation of subscriber.CiliumNodeChain
// with an additional Register method for attaching children subscribers to the
// chain.
type CiliumNodeChain struct {
	list

	subs []CiliumNode
}

// NewCiliumNodeChain creates a CiliumNodeChain ready for its
// Register method to be called.
func NewCiliumNodeChain() *CiliumNodeChain {
	return &CiliumNodeChain{}
}

// Register registers s as a subscriber for reacting to CiliumNode objects
// into the list.
func (l *CiliumNodeChain) Register(s CiliumNode) {
	l.Lock()
	l.subs = append(l.subs, s)
	l.Unlock()
}

// OnAddCiliumNode notifies all the subscribers of an add event to a CiliumNode.
func (l *CiliumNodeChain) OnAddCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnAddCiliumNode(node, swg); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// OnUpdateCiliumNode notifies all the subscribers of an update event to a CiliumNode.
func (l *CiliumNodeChain) OnUpdateCiliumNode(oldNode, newNode *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnUpdateCiliumNode(oldNode, newNode, swg); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// OnDeleteCiliumNode notifies all the subscribers of an update event to a CiliumNode.
func (l *CiliumNodeChain) OnDeleteCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnDeleteCiliumNode(node, swg); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}
