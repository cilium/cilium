// Copyright 2017 Google Inc.
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

package manager

import (
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"

	metallbk8s "go.universe.tf/metallb/pkg/k8s"
	"go.universe.tf/metallb/pkg/k8s/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// OnAdd handles an add event for services. It implements
// github.com/cilium/cilium/pkg/k8s/watchers/subscriber.ServiceHandler.
func (m *Manager) OnAdd(obj *slim_corev1.Service) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err == nil {
		m.queue.Add(svcEvent(key))
	} else {
		logInvalidObject(obj, err)
	}
}

// OnUpdate handles an update event for services. It implements
// github.com/cilium/cilium/pkg/k8s/watchers/subscriber.ServiceHandler.
func (m *Manager) OnUpdate(oldObj, newObj *slim_corev1.Service) {
	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err == nil {
		m.queue.Add(svcEvent(key))
	} else {
		logInvalidObject(newObj, err)
	}
}

// OnDelete handles a delete event for services. It implements
// github.com/cilium/cilium/pkg/k8s/watchers/subscriber.ServiceHandler.
func (m *Manager) OnDelete(obj *slim_corev1.Service) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err == nil {
		m.queue.Add(svcEvent(key))
	} else {
		logInvalidObject(obj, err)
	}
}

func logInvalidObject(obj *slim_corev1.Service, err error) {
	log.WithError(err).WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s slim_corev1 Service")
}

type svcEvent string

// run runs the reconciliation loop, fetching events off of the queue to
// process. This loop is only stopped (implicitly) when the Operator is
// shutting down.
//
// Adapted from go.universe.tf/metallb/pkg/k8s/k8s.go.
func (m *Manager) run() {
	for {
		ev, quit := m.queue.Get()
		if quit {
			return
		}
		st := m.process(ev)
		switch st {
		case types.SyncStateSuccess: // Nothing to do.
		case types.SyncStateError: // Re-add upon error to retry.
			m.queue.Add(ev)
		case types.SyncStateReprocessAll:
			// This is returned when a service is deleted. When a service is
			// deleted, then that frees up an LB IP. If there are pending
			// services waiting to be allocated an IP, then we need to
			// reprocess of the services in order to allocate an IP for the
			// ones without one.
			//
			// Adapted from
			// go.universe.tf/metallb/pkg/controller/service.go:108.

			// The other case when SyncStateReprocessAll is returned in MetalLB
			// is when the configuration changes. However, we are not watching
			// for configuration changes because our configuration is static
			// and loaded once at Cilium start time.

			m.forceResync()
		}
	}
}

// process processes the event passed in. For now only service events
// (svcEvent) are handled. If the service exists in the service indexer, then
// it will begin reconciliation. Otherwise, a service that doesn't exist means
// it was deleted, and passing down a nil object to MetalLB informs it
// deallocate the LB IP assigned to the service.
func (m *Manager) process(event interface{}) types.SyncState {
	defer m.queue.Done(event)

	switch k := event.(type) {
	case svcEvent:
		n := string(k) // service namespace/name

		svc, exists, err := m.indexer.GetByKey(n)
		if err != nil {
			return types.SyncStateError
		}
		if !exists {
			return m.reconcile(n, nil) // Causes MetalLB to unassign the LB IP
		}
		return m.reconcile(n, svc.(*slim_corev1.Service))
	default:
		log.Debugf("Encountered an unknown key type %T in BGP controller", k)
		return types.SyncStateSuccess
	}
}

// reconcile calls down to the MetalLB controller to reconcile the service
// object, which will allocate it an LB IP.
func (m *Manager) reconcile(name string, svc *slim_corev1.Service) types.SyncState {
	return m.SetBalancer(m.Logger(), name, toV1Service(svc), metallbk8s.EpsOrSlices{
		Type: metallbk8s.Eps,
	})
}

// forceResync re-adds all the services from the indexer to the queue. See
// comment inside (*Manager).sync().
func (m *Manager) forceResync() {
	for _, k := range m.indexer.ListKeys() {
		m.queue.Add(svcEvent(k))
	}
}

func toV1Service(in *slim_corev1.Service) *v1.Service {
	if in == nil {
		return nil
	}
	return &v1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       in.TypeMeta.Kind,
			APIVersion: in.TypeMeta.APIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            in.ObjectMeta.Name,
			Namespace:       in.ObjectMeta.Namespace,
			ResourceVersion: in.ObjectMeta.ResourceVersion,
			UID:             in.ObjectMeta.UID,
			Labels:          in.ObjectMeta.Labels,
			Annotations:     in.ObjectMeta.Annotations,
		},
		Spec: v1.ServiceSpec{
			Ports:                 k8s.ConvertToK8sV1ServicePorts(in.Spec.Ports),
			Selector:              in.Spec.Selector,
			ClusterIP:             in.Spec.ClusterIP,
			Type:                  v1.ServiceType(in.Spec.Type),
			ExternalIPs:           in.Spec.ExternalIPs,
			SessionAffinity:       v1.ServiceAffinity(in.Spec.SessionAffinity),
			LoadBalancerIP:        in.Spec.LoadBalancerIP,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyType(in.Spec.ExternalTrafficPolicy),
			HealthCheckNodePort:   in.Spec.HealthCheckNodePort,
			SessionAffinityConfig: k8s.ConvertToK8sV1ServiceAffinityConfig(in.Spec.SessionAffinityConfig),
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: k8s.ConvertToK8sV1LoadBalancerIngress(in.Status.LoadBalancer.Ingress),
			},
		},
	}
}
