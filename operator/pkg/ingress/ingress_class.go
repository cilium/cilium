// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"strconv"
	"sync/atomic"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// isIngressClassMarkedDefault determines if the given IngressClass has an annotation marking it as the
// default IngressClass for the cluster.
// If the annotation's value fails to parse, then an error is returned to signal that processing the
// IngressClass should be retried at a later point in time.
// There are four possible cases:
// 1. Annotation is set to "true": we are the default IngressClass.
// 2. Annotation is set to "false", a non-bool value, or is missing: we are not the default IngressClass.
func isIngressClassMarkedDefault(obj *slim_networkingv1.IngressClass) (bool, error) {
	var err error

	// If the annotation is not set, or set to an improper value,
	// we should not be the default ingress class.
	isDefault := false

	if val, ok := obj.GetAnnotations()[slim_networkingv1.AnnotationIsDefaultIngressClass]; ok {
		isDefault, err = strconv.ParseBool(val)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse annotation value for %q", slim_networkingv1.AnnotationIsDefaultIngressClass)

			return false, err
		}
	}

	return isDefault, nil
}

// isIngressClassCilium returns true if the given IngressClass resource has the same name as
// the constant 'ciliumIngressClassName'.
func isIngressClassCilium(obj *slim_networkingv1.IngressClass) bool {
	return obj.GetName() == ciliumIngressClassName
}

type ciliumIngressClassUpdatedEvent struct {
	isDefault bool
	changed   bool
}

type ciliumIngressClassDeletedEvent struct {
	wasDefault bool
}

type ingressClassManager struct {
	isDefaultIngressClass atomic.Bool
	synced                atomic.Bool
	queue                 workqueue.RateLimitingInterface
	ingressClasses        resource.Resource[*slim_networkingv1.IngressClass]
}

// newIngressClassManager creates a new ingressClassManager.
func newIngressClassManager(
	queue workqueue.RateLimitingInterface,
	ingressClasses resource.Resource[*slim_networkingv1.IngressClass],
) *ingressClassManager {
	manager := &ingressClassManager{
		isDefaultIngressClass: atomic.Bool{},
		synced:                atomic.Bool{},
		ingressClasses:        ingressClasses,
		queue:                 queue,
	}

	manager.isDefaultIngressClass.Store(false)
	manager.synced.Store(false)

	return manager
}

func (i *ingressClassManager) IsDefault() bool {
	return i.isDefaultIngressClass.Load()
}

// WaitForSync blocks until a Sync event is received from the IngressClasses Resource.
// If a Sync event has already been received, this method immediately returns.
func (i *ingressClassManager) WaitForSync(ctx context.Context) error {
	if i.synced.Load() {
		return nil
	}

	// This function will only return "false" if ctx.Done() is closed.
	// Instead of returning a bool, this method returns an error, which will
	// be easier for callers to handle.
	success := cache.WaitForNamedCacheSync(
		"ingressClassManager", ctx.Done(),
		func() bool {
			return i.synced.Load()
		},
	)

	if success {
		return nil
	}

	return ctx.Err()
}

// Run kicks off the the main control loop for the ingressClassManager.
// The ingressClassManager will start processing IngressClass events and signaling updates by
// sending events on the queue that was provided during construction.
// This method returns when the given context is cancelled or when then IngressClasses
// resource given during construction is stopped.
func (i *ingressClassManager) Run(ctx context.Context) error {
	log.Debug("Starting ingressClassManager")

	var err error

	ingressClassEvents := i.ingressClasses.Events(ctx)

	for {
		select {
		case event, ok := <-ingressClassEvents:
			if !ok {
				return nil
			}

			err = nil

			switch event.Kind {
			case resource.Sync:
				err = i.handleSyncEvent()
			case resource.Upsert:
				err = i.handleUpsertEvent(event)
			case resource.Delete:
				err = i.handleDeleteEvent(event)
			}

			event.Done(err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// handleSyncEvent handles a Sync event for the events of an IngressClasses Resource.
func (i *ingressClassManager) handleSyncEvent() error {
	log.Debug("Handling IngressClass Sync event")
	i.synced.Store(true)

	return nil
}

// handleUpsertEvent handles an Upsert event for an IngressClass resource.
// If the IngressClass has a name that is not the Cilium IngressClass name, it will be ignored.
// If an error is returned, then the IngressClass contained in the event should be retried at a later
// point in time.
func (i *ingressClassManager) handleUpsertEvent(event resource.Event[*slim_networkingv1.IngressClass]) error {
	log.WithField(logfields.IngressClass, event.Object).Warn("Handling IngressClass Upsert event")

	if event.Object == nil || !isIngressClassCilium(event.Object) {
		return nil
	}

	// Even if an error occurs due to a bad annotation value, we still need to perform an update to
	// signal that we are no longer the default ingress class.
	isDefault, err := isIngressClassMarkedDefault(event.Object)
	old := i.isDefaultIngressClass.Swap(isDefault)

	i.queue.Add(ciliumIngressClassUpdatedEvent{
		isDefault: isDefault,
		changed:   !(old == isDefault),
	})

	return err
}

// handleDeleteEvent handles a Delete event for an IngressClass resource.
// If the IngressClass has a name that is not the Cilium IngressClass name, it will be ignored.
// If an error is returned, then the IngressClass contained in the event should be retried at a later
// point in time.
func (i *ingressClassManager) handleDeleteEvent(event resource.Event[*slim_networkingv1.IngressClass]) error {
	log.WithField(logfields.IngressClass, event.Object).Debug("Handling IngressClass Delete event")

	if event.Object == nil || !isIngressClassCilium(event.Object) {
		return nil
	}

	old := i.isDefaultIngressClass.Swap(false)

	i.queue.Add(ciliumIngressClassDeletedEvent{
		wasDefault: old,
	})

	return nil
}
