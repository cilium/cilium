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

// ServiceHandler is implemented by event handlers responding to K8s Service
// events.
type ServiceHandler interface {
	OnAdd(*slim_corev1.Service)
	OnUpdate(oldObj, newObj *slim_corev1.Service)
	OnDelete(*slim_corev1.Service)
}

// NewService creates a new subscriber list for ServiceHandlers.
func NewService() *ServiceList {
	return &ServiceList{}
}

// Register registers ServiceHandler as a subscriber for reacting to Service
// objects into the list.
func (l *ServiceList) Register(s ServiceHandler) {
	l.Lock()
	l.subs = append(l.subs, s)
	l.Unlock()
}

// NotifyAdd notifies all the subscribers of an add event to a service.
func (l *ServiceList) NotifyAdd(svc *slim_corev1.Service) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnAdd(svc)
	}
}

// NotifyUpdate notifies all the subscribers of an update event to a service.
func (l *ServiceList) NotifyUpdate(oldSvc, newSvc *slim_corev1.Service) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnUpdate(oldSvc, newSvc)
	}
}

// NotifyDelete notifies all the subscribers of an update event to a service.
func (l *ServiceList) NotifyDelete(svc *slim_corev1.Service) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnDelete(svc)
	}
}

// ServiceList holds the ServiceHandler subscribers that are notified when
// reacting to K8s Service resource / object changes in the K8s watchers.
type ServiceList struct {
	list

	subs []ServiceHandler
}
