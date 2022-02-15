// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subscriber

import (
	"k8s.io/client-go/tools/cache"
)

var _ cache.ResourceEventHandler = (*RawChain)(nil)

// RawChain holds the raw subscribers to any K8s resource / object changes in
// the K8s watchers.
//
// RawChain itself is an implementation of cache.ResourceEventHandler with
// an additional Register method for attaching children subscribers to the
// chain.
type RawChain struct {
	list

	subs []cache.ResourceEventHandler
}

// NewRaw creates a new raw subscriber list.
func NewRawChain() *RawChain {
	return &RawChain{}
}

// Register registers the raw event handler as a subscriber.
func (l *RawChain) Register(cb cache.ResourceEventHandler) {
	l.Lock()
	l.subs = append(l.subs, cb)
	l.Unlock()
}

// NotifyAdd notifies all the subscribers of an add event to an object.
func (l *RawChain) OnAdd(obj interface{}) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnAdd(obj)
	}
}

// NotifyUpdate notifies all the subscribers of an update event to an object.
func (l *RawChain) OnUpdate(oldObj, newObj interface{}) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnUpdate(oldObj, newObj)
	}
}

// NotifyDelete notifies all the subscribers of an update event to an object.
func (l *RawChain) OnDelete(obj interface{}) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnDelete(obj)
	}
}
