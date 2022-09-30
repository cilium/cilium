// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	corev1 "k8s.io/api/core/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

// Event emitted from resource. One of SyncEvent, UpdateEvent or DeleteEvent.
type Event[T k8sRuntime.Object] interface {
	// Handle the event by invoking the right handler.
	// On error the event is requeued by key for later processing.
	//
	// If you use Handle(), then Done() should not be called.
	// If you need to process the events in parallel/asynchronously,
	// then do a type-switch on Event[T] and call Done() after the
	// event has been processed.
	Handle(
		onSync func(Store[T]) error,
		onUpdate func(Key, T) error,
		onDelete func(Key, T) error,
	)

	// Done marks the event as processed.  If err is non-nil, the
	// key of the object is requeued and the processing retried at
	// a later time with a potentially new version of the object.
	//
	// If you choose not to use Handle(), then this must always be called after the
	// event has been processed.
	Done(err error)
}

type baseEvent struct {
	done func(error)
}

func (b *baseEvent) Done(err error) {
	b.done(err)
}

// SyncEvent is emitted after a set of initial objects has been emitted as UpdateEvents. At this
// point the subscriber will have a consistent snapshot of the state of this resource and can
// perform e.g. garbage collection operations.
type SyncEvent[T k8sRuntime.Object] struct {
	baseEvent
	Store Store[T]
}

var _ Event[*corev1.Node] = &SyncEvent[*corev1.Node]{}

func (ev *SyncEvent[T]) Handle(onSync func(store Store[T]) error, onUpdate func(Key, T) error, onDelete func(Key, T) error) {
	ev.Done(onSync(ev.Store))
}

// UpdateEvent is emitted when an object has been added or updated
type UpdateEvent[T k8sRuntime.Object] struct {
	baseEvent
	Key    Key
	Object T
}

var _ Event[*corev1.Node] = &UpdateEvent[*corev1.Node]{}

func (ev *UpdateEvent[T]) Handle(onSync func(Store[T]) error, onUpdate func(Key, T) error, onDelete func(Key, T) error) {
	ev.Done(onUpdate(ev.Key, ev.Object))
}

// DeleteEvent is emitted when an object has been deleted
type DeleteEvent[T k8sRuntime.Object] struct {
	baseEvent
	Key    Key
	Object T
}

var _ Event[*corev1.Node] = &DeleteEvent[*corev1.Node]{}

func (ev *DeleteEvent[T]) Handle(onSync func(Store[T]) error, onUpdate func(Key, T) error, onDelete func(Key, T) error) {
	ev.Done(onDelete(ev.Key, ev.Object))
}
