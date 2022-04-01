// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subscriber

import (
	"fmt"

	"github.com/cilium/cilium/pkg/k8s/types"
)

var _ CiliumEndpoint = (*CiliumEndpointChain)(nil)

// CiliumEndpoint is implemented by event handlers responding to CiliumEndpoint events.
type CiliumEndpoint interface {
	OnAddCiliumEndpoint(cep *types.CiliumEndpoint) error
	OnUpdateCiliumEndpoint(oldEP, newCEP *types.CiliumEndpoint) error
	OnDeleteCiliumEndpoint(cep *types.CiliumEndpoint) error
}

// CiliumEndpointChain holds the subsciber.CiliumEndpoint implementations that
// are notified when reacting to CiliumEndpoint resource / object changes in
// the K8s watchers.
//
// CiliumEndpointChain itself is an implementation of
// subscriber.CiliumEndpointChain with an additional Register method for
// attaching children subscribers to the chain.
type CiliumEndpointChain struct {
	list

	subs []CiliumEndpoint
}

// NewCiliumEndpointChain creates a CiliumEndpointChain ready for its Register
// method to be called.
func NewCiliumEndpointChain() *CiliumEndpointChain {
	return &CiliumEndpointChain{}
}

// Register registers s as a subscriber for reacting to CiliumEndpoint objects
// into the list.
func (l *CiliumEndpointChain) Register(s CiliumEndpoint) {
	l.Lock()
	l.subs = append(l.subs, s)
	l.Unlock()
}

// OnAddCiliumEndpoint notifies all the subscribers of an add event to a CiliumEndpoint.
func (l *CiliumEndpointChain) OnAddCiliumEndpoint(cep *types.CiliumEndpoint) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnAddCiliumEndpoint(cep); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// OnUpdateCiliumEndpoint notifies all the subscribers of an update event to a CiliumEndpoint.
func (l *CiliumEndpointChain) OnUpdateCiliumEndpoint(oldCEP, newCEP *types.CiliumEndpoint) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnUpdateCiliumEndpoint(oldCEP, newCEP); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// OnDeleteCiliumEndpoint notifies all the subscribers of a delete event to a
// CiliumEndpoint.
func (l *CiliumEndpointChain) OnDeleteCiliumEndpoint(cep *types.CiliumEndpoint) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnDeleteCiliumEndpoint(cep); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}
