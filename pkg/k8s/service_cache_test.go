// Copyright 2018 Authors of Cilium
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

// +build !privileged_tests

package k8s

import (
	"net"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/versioned"

	"gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (s *K8sSuite) TestGetUniqueServiceFrontends(c *check.C) {
	svcID1 := ServiceID{Name: "svc1", Namespace: "default"}
	svcID2 := ServiceID{Name: "svc2", Namespace: "default"}

	endpoints := Endpoints{
		Backends: map[string]service.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	cache := NewServiceCache()
	cache.services = map[ServiceID]*Service{
		svcID1: {
			FrontendIP: net.ParseIP("1.1.1.1"),
			Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
				loadbalancer.FEPortName("foo"): {
					L4Addr: &loadbalancer.L4Addr{
						Protocol: loadbalancer.TCP,
						Port:     10,
					},
				},
				loadbalancer.FEPortName("bar"): {
					L4Addr: &loadbalancer.L4Addr{
						Protocol: loadbalancer.TCP,
						Port:     20,
					},
				},
			},
		},
		svcID2: {
			FrontendIP: net.ParseIP("2.2.2.2"),
			Ports: map[loadbalancer.FEPortName]*loadbalancer.FEPort{
				loadbalancer.FEPortName("bar"): {
					L4Addr: &loadbalancer.L4Addr{
						Protocol: loadbalancer.UDP,
						Port:     20,
					},
				},
			},
		},
	}
	cache.endpoints = map[ServiceID]*Endpoints{
		svcID1: &endpoints,
		svcID2: &endpoints,
	}

	frontends := cache.UniqueServiceFrontends()
	c.Assert(frontends, checker.DeepEquals, map[string]struct{}{
		"1.1.1.1:10/TCP": {},
		"1.1.1.1:20/TCP": {},
		"2.2.2.2:20/UDP": {},
	})
}

func (s *K8sSuite) TestServiceCache(c *check.C) {
	svcCache := NewServiceCache()

	k8sSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	svcID := svcCache.UpdateService(k8sSvc)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received before endpoints have been imported")
	default:
	}

	k8sEndpoints := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []v1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	svcCache.UpdateEndpoints(k8sEndpoints)

	// The service should be ready as both service and endpoints have been
	// imported
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, ready := svcCache.correlateEndpoints(svcID)
	c.Assert(ready, check.Equals, true)
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP")

	// Updating the service without chaning it should not result in an event
	svcCache.UpdateService(k8sSvc)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received for unchanged service object")
	default:
	}

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Reinserting the service should re-match with the still existing endpoints
	svcCache.UpdateService(k8sSvc)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Deleting the endpoints will result in a service delete event
	svcCache.DeleteEndpoints(k8sEndpoints)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, serviceReady := svcCache.correlateEndpoints(svcID)
	c.Assert(serviceReady, check.Equals, false)
	c.Assert(endpoints.String(), check.Equals, "")

	// Reinserting the endpoints should re-match with the still existing service
	svcCache.UpdateEndpoints(k8sEndpoints)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, serviceReady = svcCache.correlateEndpoints(svcID)
	c.Assert(serviceReady, check.Equals, true)
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP")

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Deleting the endpoints will not emit an event as the notification
	// was sent out when the service was deleted.
	svcCache.DeleteEndpoints(k8sEndpoints)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.Events:
		c.Error("Unexpected service delete event received")
	default:
	}

	k8sIngress := &v1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "bar",
		},
		Spec: v1beta1.IngressSpec{
			Backend: &v1beta1.IngressBackend{
				ServiceName: "svc1",
				ServicePort: intstr.IntOrString{
					IntVal: 8080,
					StrVal: "foo",
					Type:   intstr.Int,
				},
			},
		},
	}
	ingressID, err := svcCache.UpdateIngress(k8sIngress, net.ParseIP("1.1.1.1"))
	c.Assert(err, check.IsNil)

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateIngress)
		c.Assert(event.ID, check.Equals, ingressID)
		return true
	}, 2*time.Second), check.IsNil)

	// Updating the ingress without changes should not result in an event
	_, err = svcCache.UpdateIngress(k8sIngress, net.ParseIP("1.1.1.1"))
	c.Assert(err, check.IsNil)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.Events:
		c.Error("Unexpected ingress event received for unchanged ingress object")
	default:
	}

	// Deleting the ingress resource will emit a delete event
	svcCache.DeleteIngress(k8sIngress)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, DeleteIngress)
		c.Assert(event.ID, check.Equals, ingressID)
		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) Test_missingK8sEndpointsV1(c *check.C) {
	type args struct {
		m        versioned.Map
		svcCache *ServiceCache
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				svcCache := NewServiceCache()
				return args{
					svcCache: &svcCache,
					m:        versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "loadbalancer is missing an endpoint",
			setupArgs: func() args {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				})

				svcCache := NewServiceCache()
				return args{
					m:        m,
					svcCache: &svcCache,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				})
				return m
			},
		},
		{
			name: "loadbalancer contains all endpoints",
			setupArgs: func() args {
				svcCache := NewServiceCache()
				svcCache.UpdateEndpoints(&v1.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "bar",
					},
				})

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.Endpoints{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
					},
				})

				return args{
					m:        m,
					svcCache: &svcCache,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		got := args.svcCache.ListMissingEndpoints(args.m)
		c.Assert(got, checker.DeepEquals, want, check.Commentf("Test name: %q", tt.name))
	}
}

func (s *K8sSuite) Test_missingK8sServicesV1(c *check.C) {
	type args struct {
		m        versioned.Map
		svcCache *ServiceCache
	}

	k8sSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				svcCache := NewServiceCache()
				return args{
					svcCache: &svcCache,
					m:        versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "loadbalancer is missing a service",
			setupArgs: func() args {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Spec: v1.ServiceSpec{
							Type: v1.ServiceTypeClusterIP,
						},
					},
				})
				svcCache := NewServiceCache()
				return args{
					m:        m,
					svcCache: &svcCache,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: &v1.Service{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo",
							Namespace: "bar",
						},
						Spec: v1.ServiceSpec{
							Type: v1.ServiceTypeClusterIP,
						},
					},
				})
				return m
			},
		},
		{
			name: "loadbalancer contains all services",
			setupArgs: func() args {
				svcCache := NewServiceCache()
				svcCache.UpdateService(k8sSvc)

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: k8sSvc,
				})

				return args{
					m:        m,
					svcCache: &svcCache,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		got := args.svcCache.ListMissingServices(args.m)
		c.Assert(got, checker.DeepEquals, want, check.Commentf("Test name: %q", tt.name))
	}
}

func (s *K8sSuite) Test_missingK8sIngressV1Beta1(c *check.C) {
	hostIP := net.ParseIP("172.0.0.1")
	type args struct {
		m        versioned.Map
		svcCache *ServiceCache
	}

	k8sIngress := &v1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Spec: v1beta1.IngressSpec{
			Backend: &v1beta1.IngressBackend{
				ServiceName: "foo",
				ServicePort: intstr.FromInt(10),
			},
		},
	}

	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() versioned.Map
	}{
		{
			name: "both equal",
			setupArgs: func() args {
				svcCache := NewServiceCache()
				return args{
					svcCache: &svcCache,
					m:        versioned.NewMap(),
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "loadbalancer is missing an ingress",
			setupArgs: func() args {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: k8sIngress,
				})
				svcCache := NewServiceCache()
				return args{
					m:        m,
					svcCache: &svcCache,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: k8sIngress,
				})
				return m
			},
		},
		{
			name: "loadbalancer contains all ingresses",
			setupArgs: func() args {
				svcCache := NewServiceCache()
				svcCache.UpdateIngress(k8sIngress, hostIP)

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: k8sIngress,
				})

				return args{
					m:        m,
					svcCache: &svcCache,
				}
			},
			setupWanted: func() versioned.Map {
				return versioned.NewMap()
			},
		},
		{
			name: "loadbalancer contains an ingress but it's different than the one that is missing",
			setupArgs: func() args {
				svcCache := NewServiceCache()
				svcCache.UpdateIngress(&v1beta1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "bar",
					},
					Spec: v1beta1.IngressSpec{
						Backend: &v1beta1.IngressBackend{
							ServiceName: "foo",
							ServicePort: intstr.FromInt(8080),
						},
					},
				}, hostIP)

				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: k8sIngress,
				})
				return args{
					m:        m,
					svcCache: &svcCache,
				}
			},
			setupWanted: func() versioned.Map {
				m := versioned.NewMap()
				m.Add("", versioned.Object{
					Data: k8sIngress,
				})
				return m
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWanted()
		got := args.svcCache.ListMissingIngresses(args.m, hostIP)
		c.Assert(got, checker.DeepEquals, want, check.Commentf("Test name: %q", tt.name))
	}
}

func (s *K8sSuite) TestCacheActionString(c *check.C) {
	c.Assert(UpdateService.String(), check.Equals, "service-updated")
	c.Assert(DeleteService.String(), check.Equals, "service-deleted")
	c.Assert(UpdateIngress.String(), check.Equals, "ingress-updated")
	c.Assert(DeleteIngress.String(), check.Equals, "ingress-deleted")
}

func (s *K8sSuite) TestServiceMerging(c *check.C) {
	svcCache := NewServiceCache()

	k8sSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				"io.cilium/global-service": "true",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      v1.ServiceTypeClusterIP,
		},
	}

	svcID := svcCache.UpdateService(k8sSvc)

	k8sEndpoints := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []v1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	svcCache.UpdateEndpoints(k8sEndpoints)

	// The service should be ready as both service and endpoints have been
	// imported
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Merging a service update with own cluster name must not result in update
	svcCache.MergeExternalServiceUpdate(&service.ClusterService{
		Cluster:   option.Config.ClusterName,
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]service.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]service.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	})

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received")
	default:
	}

	svcCache.MergeExternalServiceUpdate(&service.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]service.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]service.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	})

	// Adding remote endpoints will trigger a service update
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)

		c.Assert(event.Endpoints.Backends["2.2.2.2"], checker.DeepEquals, service.PortConfiguration{
			"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
		})

		c.Assert(event.Endpoints.Backends["3.3.3.3"], checker.DeepEquals, service.PortConfiguration{
			"port": {Protocol: loadbalancer.TCP, Port: 80},
		})

		return true
	}, 2*time.Second), check.IsNil)

	// Merging a service for another name should not trigger any updates
	svcCache.MergeExternalServiceUpdate(&service.ClusterService{
		Cluster:   "cluster",
		Namespace: "bar",
		Name:      "foo2",
		Frontends: map[string]service.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]service.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	})

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received")
	default:
	}

	// Adding the service later must trigger an update
	svcID2 := svcCache.UpdateService(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo2",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
			Annotations: map[string]string{
				"io.cilium/global-service": "true",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.2",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	})

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID2)
		return true
	}, 2*time.Second), check.IsNil)

	cluster2svc := &service.ClusterService{
		Cluster:   "cluster2",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]service.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]service.PortConfiguration{
			"4.4.4.4": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	}

	// Adding another cluster to the first service will triger an event
	svcCache.MergeExternalServiceUpdate(cluster2svc)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)

		c.Assert(event.Endpoints.Backends["4.4.4.4"], checker.DeepEquals, service.PortConfiguration{
			"port": {Protocol: loadbalancer.TCP, Port: 80},
		})

		return true
	}, 2*time.Second), check.IsNil)

	svcCache.MergeExternalServiceDelete(cluster2svc)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.Endpoints.Backends["4.4.4.4"], check.IsNil)
		return true
	}, 2*time.Second), check.IsNil)

	// Deletion of the service frontend will trigger the delete notification
	svcCache.DeleteService(k8sSvc)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// When readding the service, the remote endpoints of cluster1 must still be present
	svcCache.UpdateService(k8sSvc)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		c.Assert(event.Endpoints.Backends["3.3.3.3"], checker.DeepEquals, service.PortConfiguration{
			"port": {Protocol: loadbalancer.TCP, Port: 80},
		})
		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestNonSharedServie(c *check.C) {
	svcCache := NewServiceCache()

	k8sSvc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				"io.cilium/global-service": "false",
			},
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      v1.ServiceTypeClusterIP,
		},
	}

	svcCache.UpdateService(k8sSvc)

	svcCache.MergeExternalServiceUpdate(&service.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Backends: map[string]service.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	})

	// The service is unshared, it should not trigger an update
	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received")
	default:
	}
}

func (s *K8sSuite) TestServiceCacheLookupEndpoints(c *check.C) {
	svcCache := NewServiceCache()
	labels := map[string]string{"foo": "bar"}

	svcSelector := &api.Service{
		K8sServiceSelector: &api.K8sServiceSelectorNamespace{
			Namespace: "bar",
			Selector:  api.NewServiceSelectorFromMatchLabels(labels),
		},
	}

	endpoints := svcCache.LookupEndpoints(svcSelector)
	c.Assert(len(endpoints), check.Equals, 0)

	svcCache.UpdateService(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar", Labels: labels},
		Spec:       v1.ServiceSpec{ClusterIP: "127.0.0.1", Type: v1.ServiceTypeClusterIP},
	})
	svcCache.UpdateEndpoints(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "foo1", Namespace: "bar"},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "2.2.2.2"}},
		}},
	})

	endpoints = svcCache.LookupEndpoints(svcSelector)
	c.Assert(endpoints, checker.DeepEquals, []*Endpoints{
		{
			Backends: map[string]service.PortConfiguration{
				"2.2.2.2": map[string]*loadbalancer.L4Addr{},
			},
		},
	})

	svcCache.UpdateService(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar", Labels: labels},
		Spec:       v1.ServiceSpec{ClusterIP: "127.0.0.2", Type: v1.ServiceTypeClusterIP},
	})
	svcCache.UpdateEndpoints(&v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: "foo2", Namespace: "bar"},
		Subsets: []v1.EndpointSubset{{
			Addresses: []v1.EndpointAddress{{IP: "3.3.3.3"}},
		}},
	})

	endpoints = svcCache.LookupEndpoints(svcSelector)
	c.Assert(len(endpoints), check.Equals, 2)
}
