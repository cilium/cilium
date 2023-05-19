// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"net"
	"time"

	check "github.com/cilium/checkmate"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/checker"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/testutils"
)

func (s *K8sSuite) TestGetUniqueServiceFrontends(c *check.C) {
	svcID1 := ServiceID{Name: "svc1", Namespace: "default"}
	svcID2 := ServiceID{Name: "svc2", Namespace: "default"}

	endpoints := Endpoints{
		Backends: map[cmtypes.AddrCluster]*Backend{
			cmtypes.MustParseAddrCluster("3.3.3.3"): {
				Ports: map[string]*loadbalancer.L4Addr{
					"port": {
						Protocol: loadbalancer.TCP,
						Port:     80,
					},
				},
			},
		},
	}

	cache := NewServiceCache(fakeDatapath.NewNodeAddressing())
	cache.services = map[ServiceID]*Service{
		svcID1: {
			FrontendIPs: []net.IP{net.ParseIP("1.1.1.1")},
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
			FrontendIPs: []net.IP{net.ParseIP("2.2.2.2")},
			Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				loadbalancer.FEPortName("bar"): {
					Protocol: loadbalancer.UDP,
					Port:     20,
				},
			},
		},
	}
	cache.endpoints = map[ServiceID]*EndpointSlices{
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

	scopes := []uint8{loadbalancer.ScopeExternal, loadbalancer.ScopeInternal}
	for _, scope := range scopes {
		// Validate all frontends as exact matches
		// These should match only for external scope
		exact_match_ok := scope == loadbalancer.ScopeExternal
		addrCluster1 := cmtypes.MustParseAddrCluster("1.1.1.1")
		addrCluster2 := cmtypes.MustParseAddrCluster("2.2.2.2")
		frontend := loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 10, scope)
		c.Assert(frontends.LooseMatch(*frontend), check.Equals, exact_match_ok)
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster1, 20, scope)
		c.Assert(frontends.LooseMatch(*frontend), check.Equals, exact_match_ok)
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.UDP, addrCluster2, 20, scope)
		c.Assert(frontends.LooseMatch(*frontend), check.Equals, exact_match_ok)

		// Validate protocol mismatch on exact match
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.TCP, addrCluster2, 20, scope)
		c.Assert(frontends.LooseMatch(*frontend), check.Equals, false)

		// Validate protocol wildcard matching
		// These should match only for external scope
		wild_match_ok := scope == loadbalancer.ScopeExternal
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, addrCluster2, 20, scope)
		c.Assert(frontends.LooseMatch(*frontend), check.Equals, wild_match_ok)
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, addrCluster1, 10, scope)
		c.Assert(frontends.LooseMatch(*frontend), check.Equals, wild_match_ok)
		frontend = loadbalancer.NewL3n4Addr(loadbalancer.NONE, addrCluster1, 20, scope)
		c.Assert(frontends.LooseMatch(*frontend), check.Equals, wild_match_ok)
	}
}

func (s *K8sSuite) TestServiceCacheEndpoints(c *check.C) {
	k8sEndpoints := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: slim_corev1.ProtocolTCP,
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
	k8sEndpointSlice := &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-afbh9",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	}

	updateEndpoints := func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice, swgEps)
	}
	deleteEndpoints := func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup) {
		svcCache.DeleteEndpointSlices(k8sEndpointSlice, swgEps)
	}

	testServiceCache(c, updateEndpoints, deleteEndpoints)
}

func testServiceCache(c *check.C,
	updateEndpointsCB, deleteEndpointsCB func(svcCache *ServiceCache, swgEps *lock.StoppableWaitGroup)) {

	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
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
	updateEndpointsCB(svcCache, swgEps)

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
	deleteEndpointsCB(svcCache, swgEps)
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
	updateEndpointsCB(svcCache, swgEps)
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
	deleteEndpointsCB(svcCache, swgEps)
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
	}, 2*time.Second), check.IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestCacheActionString(c *check.C) {
	c.Assert(UpdateService.String(), check.Equals, "service-updated")
	c.Assert(DeleteService.String(), check.Equals, "service-deleted")
}

func (s *K8sSuite) TestServiceMutators(c *check.C) {
	var m1, m2 int

	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())
	svcCache.ServiceMutators = append(svcCache.ServiceMutators,
		func(svc *slim_corev1.Service, svcInfo *Service) { m1++ },
		func(svc *slim_corev1.Service, svcInfo *Service) { m2++ },
	)
	swg := lock.NewStoppableWaitGroup()
	svcCache.UpdateService(&slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector:  map[string]string{"foo": "bar"},
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}, swg)

	// Assert that the service mutators configured have been executed.
	c.Assert(m1, check.Equals, 1)
	c.Assert(m2, check.Equals, 1)
}

func (s *K8sSuite) TestExternalServiceMerging(c *check.C) {
	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				"service.cilium.io/global": "true",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
			Ports: []slim_corev1.ServicePort{
				{
					Name:     "foo",
					Protocol: slim_corev1.ProtocolTCP,
					Port:     80,
				},
			},
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcID := svcCache.UpdateService(k8sSvc, swgSvcs)

	k8sEndpoints := &slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: slim_corev1.ProtocolTCP,
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
	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   option.Config.ClusterName,
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
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

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: false,
		Shared:          false,
	},
		swgSvcs,
	)

	// Adding non-shared remote endpoints will not trigger a service update, regardless of whether
	// IncludeExternal is set (i.e., the service is marked as a global one in the remote cluster).
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)

		c.Assert(len(event.Endpoints.Backends), checker.Equals, 1)
		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("2.2.2.2")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		})

		return true
	}, 2*time.Second), check.IsNil)

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          false,
	},
		swgSvcs,
	)

	// Adding non-shared remote endpoints will not trigger a service update, regardless of whether
	// IncludeExternal is set (i.e., the service is marked as a global one in the remote cluster).
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)

		c.Assert(len(event.Endpoints.Backends), checker.Equals, 1)
		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("2.2.2.2")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		})

		return true
	}, 2*time.Second), check.IsNil)

	// We do not test the case with shared remote endpoints and IncludeExternal not set
	// (i.e., the service is not marked as a global one in the remote cluster).
	// Indeed, this condition shall never happen, since a shared service shall always be global.

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          true,
	},
		swgSvcs,
	)

	// Adding shared remote endpoints will trigger a service update, in case IncludeExternal
	// is set (i.e., the service is marked as a global one in the remote cluster).
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)

		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("2.2.2.2")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		})

		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("3.3.3.3")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		})

		return true
	}, 2*time.Second), check.IsNil)

	// Merging a service for another name should not trigger any updates
	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster",
		Namespace: "bar",
		Name:      "foo2",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          true,
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
	svcID2 := svcCache.UpdateService(
		&slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "foo2",
				Namespace: "bar",
				Labels: map[string]string{
					"foo": "bar",
				},
				Annotations: map[string]string{
					"service.cilium.io/global": "true",
				},
			},
			Spec: slim_corev1.ServiceSpec{
				ClusterIP: "127.0.0.2",
				Selector: map[string]string{
					"foo": "bar",
				},
				Type: slim_corev1.ServiceTypeClusterIP,
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

	cluster2svc := &serviceStore.ClusterService{
		Cluster:   "cluster2",
		Namespace: "bar",
		Name:      "foo",
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"4.4.4.4": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: true,
		Shared:          true,
	}

	// Adding another cluster to the first service will trigger an event
	svcCache.MergeExternalServiceUpdate(cluster2svc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)

		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("4.4.4.4")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
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
		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("4.4.4.4")], check.IsNil)
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

	// When re-adding the service, the remote endpoints of cluster1 must still be present
	svcCache.UpdateService(k8sSvc, swgSvcs)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("3.3.3.3")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		})
		return true
	}, 2*time.Second), check.IsNil)

	k8sSvcID, _ := ParseService(k8sSvc, nil)
	addresses := svcCache.GetServiceIP(k8sSvcID)
	c.Assert(addresses, checker.DeepEquals, loadbalancer.NewL3n4Addr(loadbalancer.TCP, cmtypes.MustParseAddrCluster("127.0.0.1"), 80, loadbalancer.ScopeExternal))

	swgSvcs.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgSvcs.Wait()
		return true
	}, 2*time.Second), check.IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestExternalServiceDeletion(c *check.C) {
	const cluster = "cluster"

	createEndpoints := func(clusters ...string) externalEndpoints {
		eeps := newExternalEndpoints()
		for i, cluster := range clusters {
			eps := newEndpoints()
			eps.Backends[cmtypes.MustParseAddrCluster(fmt.Sprintf("1.1.1.%d", i))] = &Backend{}
			eeps.endpoints[cluster] = eps
		}

		return eeps
	}

	svc := Service{IncludeExternal: true, Shared: true}
	clsvc := serviceStore.ClusterService{Cluster: cluster, Namespace: "bar", Name: "foo"}
	id1 := ServiceID{Namespace: "bar", Name: "foo"}
	id2 := ServiceID{Cluster: cluster, Namespace: "bar", Name: "foo"}

	swg := lock.NewStoppableWaitGroup()
	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	// Store the service with the non-cluster-aware ID
	svcCache.services[id1] = &svc
	svcCache.externalEndpoints[id1] = createEndpoints(cluster)

	svcCache.MergeExternalServiceDelete(&clsvc, swg)
	_, ok := svcCache.services[id1]
	c.Assert(ok, check.Equals, false)
	_, ok = svcCache.externalEndpoints[id1]
	c.Assert(ok, check.Equals, false)

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, id1)
		return true
	}, 2*time.Second), check.IsNil)

	// Store the service with the non-cluster-aware ID and multiple endpoints
	svcCache.services[id1] = &svc
	svcCache.externalEndpoints[id1] = createEndpoints(cluster, "other")

	svcCache.MergeExternalServiceDelete(&clsvc, swg)
	_, ok = svcCache.services[id1]
	c.Assert(ok, check.Equals, true)
	_, ok = svcCache.externalEndpoints[id1]
	c.Assert(ok, check.Equals, true)
	_, ok = svcCache.externalEndpoints[id1].endpoints[cluster]
	c.Assert(ok, check.Equals, false)

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, id1)
		return true
	}, 2*time.Second), check.IsNil)

	// Store the service with the cluster-aware ID
	svcCache.services[id2] = &svc
	svcCache.externalEndpoints[id2] = createEndpoints(cluster)

	svcCache.MergeExternalServiceDelete(&clsvc, swg)
	_, ok = svcCache.services[id2]
	c.Assert(ok, check.Equals, false)
	_, ok = svcCache.externalEndpoints[id2]
	c.Assert(ok, check.Equals, false)

	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, DeleteService)
		c.Assert(event.ID, check.Equals, id2)
		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestClusterServiceMerging(c *check.C) {
	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())
	swgSvcs := lock.NewStoppableWaitGroup()
	swgEps := lock.NewStoppableWaitGroup()

	svcID := ServiceID{Name: "foo", Namespace: "bar"}

	svcCache.UpdateEndpoints(&slim_corev1.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Namespace: svcID.Namespace,
			Name:      svcID.Name,
		},
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{{IP: "2.2.2.2"}},
				Ports: []slim_corev1.EndpointPort{
					{
						Name:     "http-test-svc",
						Port:     8080,
						Protocol: slim_corev1.ProtocolTCP,
					},
				},
			},
		},
	}, swgEps)

	svcCache.MergeClusterServiceUpdate(&serviceStore.ClusterService{
		Cluster:   option.Config.ClusterName,
		Namespace: svcID.Namespace,
		Name:      svcID.Name,
		Frontends: map[string]serviceStore.PortConfiguration{
			"1.1.1.1": {},
		},
		Backends: map[string]serviceStore.PortConfiguration{
			"3.3.3.3": map[string]*loadbalancer.L4Addr{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		},
		IncludeExternal: false,
		Shared:          false,
	}, swgSvcs)

	// Adding a service will trigger the corresponding update containing all ready backends,
	// regardless of whether it is marked as global or shared (since the cluster name matches).
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		defer event.SWG.Done()
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)

		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("2.2.2.2")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
				"http-test-svc": {Protocol: loadbalancer.TCP, Port: 8080},
			},
		})

		c.Assert(event.Endpoints.Backends[cmtypes.MustParseAddrCluster("3.3.3.3")], checker.DeepEquals, &Backend{
			Ports: serviceStore.PortConfiguration{
				"port": {Protocol: loadbalancer.TCP, Port: 80},
			},
		})

		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestNonSharedService(c *check.C) {
	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				"service.cilium.io/global": "false",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	svcCache.UpdateService(k8sSvc, swgSvcs)

	svcCache.MergeExternalServiceUpdate(&serviceStore.ClusterService{
		Cluster:   "cluster1",
		Namespace: "bar",
		Name:      "foo",
		Backends: map[string]serviceStore.PortConfiguration{
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
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestServiceCacheWith2EndpointSlice(c *check.C) {
	k8sEndpointSlice1 := &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-yyyyy",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	}

	k8sEndpointSlice2 := &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-xxxxx",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.3",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	}

	k8sEndpointSlice3 := &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-xxxxx",
			Namespace: "baz",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.4",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	}

	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
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
	svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice1, swgEps)
	svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice2, swgEps)
	svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice3, swgEps)

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
	svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice1, swgEps)
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
	}, 2*time.Second), check.IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestServiceCacheWith2EndpointSliceSameAddress(c *check.C) {
	k8sEndpointSlice1 := &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-yyyyy",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8080); return &a }(),
			},
		},
	}

	k8sEndpointSlice2 := &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-xxxxx",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{
					"2.2.2.2",
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http-test-svc2"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(8081); return &a }(),
			},
		},
	}

	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector: map[string]string{
				"foo": "bar",
			},
			Type: slim_corev1.ServiceTypeClusterIP,
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
	svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice1, swgEps)
	svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice2, swgEps)

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
	c.Assert(endpoints.String(), check.Equals, "2.2.2.2:8080/TCP,2.2.2.2:8081/TCP")

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
	svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice1, swgEps)
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
	}, 2*time.Second), check.IsNil)

	swgEps.Stop()
	c.Assert(testutils.WaitUntil(func() bool {
		swgEps.Wait()
		return true
	}, 2*time.Second), check.IsNil)
}

func (s *K8sSuite) TestServiceEndpointFiltering(c *check.C) {
	k8sSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Labels:    map[string]string{"foo": "bar"},
			Annotations: map[string]string{
				v1.AnnotationTopologyAwareHints: "auto",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			ClusterIP: "127.0.0.1",
			Selector:  map[string]string{"foo": "bar"},
			Type:      slim_corev1.ServiceTypeClusterIP,
		},
	}
	veryTrue := true
	k8sEndpointSlice := &slim_discovery_v1.EndpointSlice{
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-ep-filtering",
			Namespace: "bar",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "foo",
			},
		},
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{"10.0.0.1"},
				Hints: &slim_discovery_v1.EndpointHints{
					ForZones: []slim_discovery_v1.ForZone{{Name: "test-zone-1"}},
				},
				Conditions: slim_discovery_v1.EndpointConditions{Ready: &veryTrue},
			},
			{
				Addresses: []string{"10.0.0.2"},
				Hints: &slim_discovery_v1.EndpointHints{
					ForZones: []slim_discovery_v1.ForZone{{Name: "test-zone-2"}},
				},
				Conditions: slim_discovery_v1.EndpointConditions{Ready: &veryTrue},
			},
		},
	}
	k8sNode := &slim_corev1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:   "node1",
			Labels: map[string]string{v1.LabelTopologyZone: "test-zone-2"},
		},
	}

	oldOptionEnableServiceTopology := option.Config.EnableServiceTopology
	defer func() { option.Config.EnableServiceTopology = oldOptionEnableServiceTopology }()
	option.Config.EnableServiceTopology = true

	svcCache := NewServiceCache(fakeDatapath.NewNodeAddressing())

	swg := lock.NewStoppableWaitGroup()

	// Send self node update to set the node's zone label
	svcCache.OnAddNode(k8sNode, swg)

	// Now update service and endpointslice. This should result in the service
	// update with 2.2.2.2 endpoint due to the zone filtering.
	svcID0 := svcCache.UpdateService(k8sSvc, swg)
	svcID1, eps := svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice, swg)
	c.Assert(svcID0, check.Equals, svcID1)
	c.Assert(len(eps.Backends), check.Equals, 1)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID0)
		c.Assert(len(event.Endpoints.Backends), check.Equals, 1)
		_, found := event.Endpoints.Backends[cmtypes.MustParseAddrCluster("10.0.0.2")]
		c.Assert(found, check.Equals, true)
		return true
	}, 2*time.Second), check.IsNil)

	// Send self node update to remove the node's zone label. This should
	// generate the service update with both endpoints selected
	k8sNode.ObjectMeta.Labels = nil
	svcCache.OnUpdateNode(k8sNode, k8sNode, swg)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID0)
		c.Assert(len(event.Endpoints.Backends), check.Equals, 2)
		return true
	}, 2*time.Second), check.IsNil)

	// Set the node's zone to test-zone-1 to select the first endpoint
	k8sNode.ObjectMeta.Labels = map[string]string{
		v1.LabelTopologyZone: "test-zone-1",
	}
	svcCache.OnUpdateNode(k8sNode, k8sNode, swg)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID0)
		c.Assert(len(event.Endpoints.Backends), check.Equals, 1)
		_, found := event.Endpoints.Backends[cmtypes.MustParseAddrCluster("10.0.0.1")]
		c.Assert(found, check.Equals, true)
		return true
	}, 2*time.Second), check.IsNil)

	// Remove the service hint, so that all endpoints all selected again
	annotations := k8sSvc.ObjectMeta.Annotations
	k8sSvc.ObjectMeta.Annotations = nil
	svcID0 = svcCache.UpdateService(k8sSvc, swg)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID0)
		c.Assert(len(event.Endpoints.Backends), check.Equals, 2)
		return true
	}, 2*time.Second), check.IsNil)

	// Set the hint back and the filtering should be back
	k8sSvc.ObjectMeta.Annotations = annotations
	svcID0 = svcCache.UpdateService(k8sSvc, swg)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID0)
		c.Assert(len(event.Endpoints.Backends), check.Equals, 1)
		return true
	}, 2*time.Second), check.IsNil)

	// Remove the zone hints. This should select all endpoints
	k8sEndpointSlice.Endpoints[0].Hints = nil
	k8sEndpointSlice.Endpoints[1].Hints = nil
	svcID1, _ = svcCache.UpdateEndpointSlicesV1(k8sEndpointSlice, swg)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID1)
		c.Assert(len(event.Endpoints.Backends), check.Equals, 2)
		return true
	}, 2*time.Second), check.IsNil)
}
