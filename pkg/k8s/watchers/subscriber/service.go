// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subscriber

import (
	"fmt"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var _ Service = (*ServiceChain)(nil)

// Service is implemented by event handlers responding to K8s Service
// events.
type Service interface {
	OnAddService(*slim_corev1.Service) error
	OnUpdateService(oldObj, newObj *slim_corev1.Service) error
	OnDeleteService(*slim_corev1.Service) error
}

// ServiceChain holds the subscriber.Service implementations that are notified when
// reacting to K8s Service resource / object changes in the K8s watchers.
//
// ServiceChain itself is an implementation of subscriber.Service with
// an additional Register method for attaching children subscribers to the
// chain.
type ServiceChain struct {
	list

	subs []Service
}

// NewServiceChain
func NewServiceChain() *ServiceChain {
	return &ServiceChain{}
}

// Register registers ServiceHandler as a subscriber for reacting to Service
// objects into the list.
func (l *ServiceChain) Register(s Service) {
	l.Lock()
	l.subs = append(l.subs, s)
	l.Unlock()
}

// OnAddService notifies all the subscribers of an add event to a service.
func (l *ServiceChain) OnAddService(svc *slim_corev1.Service) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnAddService(svc); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// OnUpdateService notifies all the subscribers of an update event to a service.
func (l *ServiceChain) OnUpdateService(oldSvc, newSvc *slim_corev1.Service) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnUpdateService(oldSvc, newSvc); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}

// OnDeleteService notifies all the subscribers of an update event to a service.
func (l *ServiceChain) OnDeleteService(svc *slim_corev1.Service) error {
	l.RLock()
	defer l.RUnlock()
	errs := []error{}
	for _, s := range l.subs {
		if err := s.OnDeleteService(svc); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Errors: %v", errs)
	}
	return nil
}
