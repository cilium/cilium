// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package subscriber

import (
	"k8s.io/client-go/tools/cache"
)

// NewRaw creates a new raw subscriber list.
func NewRaw() *RawList {
	return &RawList{}
}

// Register registers the raw event handler as a subscriber.
func (l *RawList) Register(cb cache.ResourceEventHandler) {
	l.Lock()
	l.subs = append(l.subs, cache.ResourceEventHandlerFuncs{
		AddFunc:    cb.OnAdd,
		UpdateFunc: cb.OnUpdate,
		DeleteFunc: cb.OnDelete,
	})
	l.Unlock()
}

// NotifyAdd notifies all the subscribers of an add event to an object.
func (l *RawList) NotifyAdd(obj interface{}) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnAdd(obj)
	}
}

// NotifyUpdate notifies all the subscribers of an update event to an object.
func (l *RawList) NotifyUpdate(oldObj, newObj interface{}) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnUpdate(oldObj, newObj)
	}
}

// NotifyDelete notifies all the subscribers of an update event to an object.
func (l *RawList) NotifyDelete(obj interface{}) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnDelete(obj)
	}
}

// RawList holds the raw subscribers to any K8s resource / object changes in
// the K8s watchers.
type RawList struct {
	list

	subs []cache.ResourceEventHandlerFuncs
}
