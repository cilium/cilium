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
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// NodeHandler is implemented by event handlers responding to K8s Node events.
type NodeHandler interface {
	OnAddNode(*slim_corev1.Node) error
	OnUpdateNode(oldObj, newObj *slim_corev1.Node) error
	OnDeleteNode(*slim_corev1.Node) error
}

// NewNode creates a new subscriber list for NodeHandlers.
func NewNode() *NodeList {
	return &NodeList{}
}

// Register registers NodeHandler as a subscriber for reacting to Node objects
// into the list.
func (l *NodeList) Register(s NodeHandler) {
	l.Lock()
	l.subs = append(l.subs, s)
	l.Unlock()
}

// NotifyAdd notifies all the subscribers of an add event to a service.
func (l *NodeList) NotifyAdd(node *slim_corev1.Node) []error {
	l.RLock()
	defer l.RUnlock()
	errs := make([]error, 0, len(l.subs))
	for _, s := range l.subs {
		if err := s.OnAddNode(node); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// NotifyUpdate notifies all the subscribers of an update event to a service.
func (l *NodeList) NotifyUpdate(oldNode, newNode *slim_corev1.Node) []error {
	l.RLock()
	defer l.RUnlock()
	errs := make([]error, 0, len(l.subs))
	for _, s := range l.subs {
		if err := s.OnUpdateNode(oldNode, newNode); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// NotifyDelete notifies all the subscribers of an update event to a service.
func (l *NodeList) NotifyDelete(node *slim_corev1.Node) []error {
	l.RLock()
	defer l.RUnlock()
	errs := make([]error, 0, len(l.subs))
	for _, s := range l.subs {
		if err := s.OnDeleteNode(node); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// NodeList holds the NodeHandler subscribers that are notified when reacting
// to K8s Node resource / object changes in the K8s watchers.
type NodeList struct {
	list

	subs []NodeHandler
}
