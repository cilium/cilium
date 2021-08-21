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
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// NewCEB creates a new ceb subscriber list.
func NewCEB() *CEBList {
	return &CEBList{}
}

// CEBHandler is implemented by event handlers responding to
// CiliumEndpointBatch events.
type CEBHandler interface {
	OnAdd(ceb *cilium_v2a1.CiliumEndpointBatch)
	OnUpdate(oldCeb, newCeb *cilium_v2a1.CiliumEndpointBatch)
	OnDelete(ceb *cilium_v2a1.CiliumEndpointBatch)
}

// Register registers the CEB event handler as a subscriber.
func (l *CEBList) Register(c CEBHandler) {
	l.Lock()
	defer l.Unlock()
	l.subs = append(l.subs, c)
}

// NotifyAdd notifies all the subscribers of an add event to an object.
func (l *CEBList) NotifyAdd(ceb *cilium_v2a1.CiliumEndpointBatch) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnAdd(ceb)
	}
}

// NotifyUpdate notifies all the subscribers of an update event to an object.
func (l *CEBList) NotifyUpdate(oldCeb, newCeb *cilium_v2a1.CiliumEndpointBatch) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnUpdate(oldCeb, newCeb)
	}
}

// NotifyDelete notifies all the subscribers of a delete event to an object.
func (l *CEBList) NotifyDelete(ceb *cilium_v2a1.CiliumEndpointBatch) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnDelete(ceb)
	}
}

// CEBList holds the CEB subscribers to any CiliumEndpointBatch resource / object changes in
// the K8s watchers.
type CEBList struct {
	list
	subs []CEBHandler
}
