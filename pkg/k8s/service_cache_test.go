// Copyright 2018-2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/testutils"

	"gopkg.in/check.v1"
	. "gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	"k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *K8sSuite) TestGetUniqueServiceFrontends(c *check.C) {
	svcID1 := ServiceID{Name: "svc1", Namespace: "default"}
	svcID2 := ServiceID{Name: "svc2", Namespace: "default"}

	endpoints := Endpoints{
		Backends: map[string]*Backend{
			"3.3.3.3": {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}

	cache := NewServiceCache()
	cache.services = map[ServiceID]*Service{
		svcID1: {
			FrontendIP: net.ParseIP("1.1.1.1"),
			Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				loadbalancer.FEPortName("foo"): {
					Protocol: loadbalancer.TCP,
					Port:     10,
				},
				loadbalancer.FEPortName("bar"): {
					Protocol: loadbalancer.TCP,
					Port:     20,
				},
			},
		},
		svcID2: {
			FrontendIP: net.ParseIP("2.2.2.2"),
			Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				loadbalancer.FEPortName("bar"): {
					Protocol: loadbalancer.UDP,
					Port:     20,
				},
			},
		},
	}
	cache.endpoints = map[ServiceID]*endpointSlices{
		svcID1: {
			epSlices: map[string]*Endpoints{
				"": &endpoints,
			},
		},
		svcID2: {
			epSlices: map[string]*Endpoints{
				"": &endpoints,
			},
		},
	}

	frontends := cache.UniqueServiceFrontends()
	c.Assert(frontends, checker.DeepEquals, FrontendList{
		"1.1.1.1:10/TCP": {},
		"1.1.1.1:20/TCP": {},
		"2.2.2.2:20/UDP": {},
	})

	// Validate all frontends as exact matches
	frontend := loadbalancer.NewL3n4Addr(loadbalancer.TCP, net.ParseIP("1.1.1.1"), 10)
	c.Assert(frontends.LooseMatch(*frontend), check.Equals, true)
	frontend = loadbalancer.NewL3n4Addr(loadbalancer.TCP, net.ParseIP("1.1.1.1"), 20)
	c.Assert(frontends.LooseMatch(*frontend), check.Equals, true)
	frontend = loadbalancer.NewL3n4Addr(loadbalancer.UDP, net.ParseIP("2.2.2.2"), 20)
	c.Assert(frontends.LooseMatch(*frontend), check.Equals, true)

	// Validate protocol mismatch on exact match
	frontend = loadbalancer.NewL3n4Addr(loadbalancer.TCP, net.ParseIP("2.2.2.2"), 20)
	c.Assert(frontends.LooseMatch(*frontend), check.Equals, false)

	// Validate protocol wildcard matching
	frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, net.ParseIP("2.2.2.2"), 20)
	c.Assert(frontends.LooseMatch(*frontend), check.Equals, true)
	frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, net.ParseIP("1.1.1.1"), 10)
	c.Assert(frontends.LooseMatch(*frontend), check.Equals, true)
	frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, net.ParseIP("1.1.1.1"), 20)
	c.Assert(frontends.LooseMatch(*frontend), check.Equals, true)
}

func (s *K8sSuite) TestServiceCacheEndpoints(c *check.C) {
	k8sEndpoints := &types.Endpoints{
		Endpoints: &v1.Endpoints{
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
		},
	}

	updateEndpoints := func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.UpdateEndpoints(k8sEndpoints, swgEps)
	}
	deleteEndpoints := func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.DeleteEndpoints(k8sEndpoints, swgEps)
	}

	testServiceCache(c, updateEndpoints, deleteEndpoints)
}

func (s *K8sSuite) TestServiceCacheEndpointSlice(c *check.C) {
	k8sEndpointSlice := &types.EndpointSlice{
		EndpointSlice: &v1beta1.EndpointSlice{
			AddressType: v1beta1.AddressTypeIPv4,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-afbh9",
				Namespace: "bar",
				Labels: map[string]string{
					v1beta1.LabelServiceName: "foo",
				},
			},
			Endpoints: []v1beta1.Endpoint{
				{
					Addresses: []string{
						"2.2.2.2",
					},
				},
			},
			Ports: []v1beta1.EndpointPort{
				{
					Name:     func() *string { a := "http-test-svc"; return &a }(),
					Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port:     func() *int32 { a := int32(8080); return &a }(),
				},
			},
		},
	}

	updateEndpoints := func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.UpdateEndpointSlices(k8sEndpointSlice, swgEps)
	}
	deleteEndpoints := func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.DeleteEndpointSlices(k8sEndpointSlice, swgEps)
	}

	testServiceCache(c, updateEndpoints, deleteEndpoints)
}

func testServiceCache(c *check.C,
	updateEndpointsCB, deleteEndpointsCB func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup)) {

	svcCache := NewServiceCache()

	k8sSvc := &types.Service{
		Service: &v1.Service{
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
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received before endpoints have been imported")
	default:
	}

	swgEps := lock.NewStoppableWaitGroup()
	updateEndpointsCB(&svcCache, swgEps)

	// The service should be ready as both service and endpoints have been
	// imported
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, ready := svcCache.correlateEndpoints(svcID)
	c.Assert(ready, check.Equals, true)
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP")

	// Updating the service without chaning it should not result in an event
	svcCache.UpdateService(k8sSvc, swgSvcs)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received for unchanged service object")
	default:
	}

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Reinserting the service should re-match with the still existing endpoints
	svcCache.UpdateService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Deleting the endpoints will result in a service update event
	deleteEndpointsCB(&svcCache, swgEps)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, serviceReady := svcCache.correlateEndpoints(svcID)
	c.Assert(serviceReady, check.Equals, false)
	c.Assert(endpoints.String(), check.Equals, "")

	// Reinserting the endpoints should re-match with the still existing service
	updateEndpointsCB(&svcCache, swgEps)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, serviceReady = svcCache.correlateEndpoints(svcID)
	c.Assert(serviceReady, check.Equals, true)
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP")

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Deleting the endpoints will not emit an event as the notification
	// was sent out when the service was deleted.
	deleteEndpointsCB(&svcCache, swgEps)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.Events:
		c.Error("Unexpected service delete event received")
	default:
	}

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), IsNil)
}

func (s *K8sSuite) TestCacheActionString(c *check.C) {
	c.Assert(UpdateService.String(), check.Equals, "service-updated")
	c.Assert(DeleteService.String(), check.Equals, "service-deleted")
}

func (s *K8sSuite) TestServiceMerging(c *check.C) {
	svcCache := NewServiceCache()

	k8sSvc := &types.Service{
		Service: &v1.Service{
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
				Ports: []v1.ServicePort{
					{
						Name:     "foo",
						Protocol: v1.ProtocolTCP,
						Port:     80,
					},
				},
			},
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	k8sEndpoints := &types.Endpoints{
		Endpoints: &v1.Endpoints{
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
		},
	}

	swgEps := lock.NewStoppableWaitGroup()
	svcCache.UpdateEndpoints(k8sEndpoints, swgEps)

	// The service should be ready as both service and endpoints have been
	// imported
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
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
	},
		swgSvcs,
	)

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
	},
		swgSvcs,
	)

	// Adding remote endpoints will trigger a service update
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)

		c.Assert(event.Endpoints.Backends["2.2.2.2"], checker.DeepEquals, &Backend{
			Ports: service.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		})

		c.Assert(event.Endpoints.Backends["3.3.3.3"], checker.DeepEquals, &Backend{
			Ports: service.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
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
	},
		swgSvcs,
	)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received")
	default:
	}

	// Adding the service later must trigger an update
	svcID2 := svcCache.UpdateService(&types.Service{
		Service: &v1.Service{
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
		},
	},
		swgSvcs,
	)

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
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
	svcCache.MergeExternalServiceUpdate(cluster2svc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)

		c.Assert(event.Endpoints.Backends["4.4.4.4"], checker.DeepEquals, &Backend{
			Ports: service.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		})

		return true
	}, 2*time.Second), check.IsNil)

	svcCache.MergeExternalServiceDelete(cluster2svc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.Endpoints.Backends["4.4.4.4"], check.IsNil)
		return true
	}, 2*time.Second), check.IsNil)

	// Deletion of the service frontend will trigger the delete notification
	svcCache.DeleteService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// When readding the service, the remote endpoints of cluster1 must still be present
	svcCache.UpdateService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		c.Assert(event.Endpoints.Backends["3.3.3.3"], checker.DeepEquals, &Backend{
			Ports: service.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		})
		return true
	}, 2*time.Second), check.IsNil)

	k8sSvcID, _ := ParseService(k8sSvc)
	addresses := svcCache.GetServiceIP(k8sSvcID)
	c.Assert(addresses, checker.DeepEquals, loadbalancer.NewL3n4Addr(loadbalancer.TCP, net.ParseIP("127.0.0.1"), 80))

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), IsNil)
}

func (s *K8sSuite) TestNonSharedServie(c *check.C) {
	svcCache := NewServiceCache()

	k8sSvc := &types.Service{
		Service: &v1.Service{
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
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcCache.UpdateService(k8sSvc, swgSvcs)

	svcCache.MergeExternalServiceUpdate(&service.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Backends: map[string]service.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
	},
		swgSvcs,
	)

	// The service is unshared, it should not trigger an update
	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received")
	default:
	}

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), IsNil)
}

func (s *K8sSuite) TestServiceCacheWith2EndpointSlice(c *check.C) {
	k8sEndpointSlice1 := &types.EndpointSlice{
		EndpointSlice: &v1beta1.EndpointSlice{
			AddressType: v1beta1.AddressTypeIPv4,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-yyyyy",
				Namespace: "bar",
				Labels: map[string]string{
					v1beta1.LabelServiceName: "foo",
				},
			},
			Endpoints: []v1beta1.Endpoint{
				{
					Addresses: []string{
						"2.2.2.2",
					},
				},
			},
			Ports: []v1beta1.EndpointPort{
				{
					Name:     func() *string { a := "http-test-svc"; return &a }(),
					Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port:     func() *int32 { a := int32(8080); return &a }(),
				},
			},
		},
	}

	k8sEndpointSlice2 := &types.EndpointSlice{
		EndpointSlice: &v1beta1.EndpointSlice{
			AddressType: v1beta1.AddressTypeIPv4,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-xxxxx",
				Namespace: "bar",
				Labels: map[string]string{
					v1beta1.LabelServiceName: "foo",
				},
			},
			Endpoints: []v1beta1.Endpoint{
				{
					Addresses: []string{
						"2.2.2.3",
					},
				},
			},
			Ports: []v1beta1.EndpointPort{
				{
					Name:     func() *string { a := "http-test-svc"; return &a }(),
					Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port:     func() *int32 { a := int32(8080); return &a }(),
				},
			},
		},
	}

	k8sEndpointSlice3 := &types.EndpointSlice{
		EndpointSlice: &v1beta1.EndpointSlice{
			AddressType: v1beta1.AddressTypeIPv4,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-xxxxx",
				Namespace: "baz",
				Labels: map[string]string{
					v1beta1.LabelServiceName: "foo",
				},
			},
			Endpoints: []v1beta1.Endpoint{
				{
					Addresses: []string{
						"2.2.2.4",
					},
				},
			},
			Ports: []v1beta1.EndpointPort{
				{
					Name:     func() *string { a := "http-test-svc"; return &a }(),
					Protocol: func() *v1.Protocol { a := v1.ProtocolTCP; return &a }(),
					Port:     func() *int32 { a := int32(8080); return &a }(),
				},
			},
		},
	}

	svcCache := NewServiceCache()

	k8sSvc := &types.Service{
		Service: &v1.Service{
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
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	time.Sleep(100 * time.Millisecond)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received before endpoints have been imported")
	default:
	}

	swgEps := lock.NewStoppableWaitGroup()
	svcCache.UpdateEndpointSlices(k8sEndpointSlice1, swgEps)
	svcCache.UpdateEndpointSlices(k8sEndpointSlice2, swgEps)
	svcCache.UpdateEndpointSlices(k8sEndpointSlice3, swgEps)

	// The service should be ready as both service and endpoints have been
	// imported for k8sEndpointSlice1
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// The service should be ready as both service and endpoints have been
	// imported for k8sEndpointSlice2
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received when endpoints not selected by a service have been imported")
	default:
	}
	endpoints, ready := svcCache.correlateEndpoints(svcID)
	c.Assert(ready, check.Equals, true)
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP,2.2.2.3:8080/TCP")

	// Updating the service without changing it should not result in an event
	svcCache.UpdateService(k8sSvc, swgSvcs)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.Events:
		c.Error("Unexpected service event received for unchanged service object")
	default:
	}

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Reinserting the service should re-match with the still existing endpoints
	svcCache.UpdateService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Deleting the k8sEndpointSlice2 will result in a service update event
	svcCache.DeleteEndpointSlices(k8sEndpointSlice2, swgEps)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, ready = svcCache.correlateEndpoints(svcID)
	c.Assert(ready, check.Equals, true)
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP")

	svcCache.DeleteEndpointSlices(k8sEndpointSlice1, swgEps)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, serviceReady := svcCache.correlateEndpoints(svcID)
	c.Assert(serviceReady, check.Equals, false)
	c.Assert(endpoints.String(), check.Equals, "")

	// Reinserting the endpoints should re-match with the still existing service
	svcCache.UpdateEndpointSlices(k8sEndpointSlice1, swgEps)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	endpoints, serviceReady = svcCache.correlateEndpoints(svcID)
	c.Assert(serviceReady, check.Equals, true)
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP")

	// Deleting the service will result in a service delete event
	svcCache.DeleteService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

	// Deleting the endpoints will not emit an event as the notification
	// was sent out when the service was deleted.
	svcCache.DeleteEndpointSlices(k8sEndpointSlice1, swgEps)
	time.Sleep(100 * time.Millisecond)
	select {
	case <-svcCache.Events:
		c.Error("Unexpected service delete event received")
	default:
	}

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), IsNil)
}
