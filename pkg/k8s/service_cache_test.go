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
	"github.com/cilium/cilium/pkg/testutils"

	"gopkg.in/check.v1"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (s *K8sSuite) TestGetUniqueServiceFronends(c *check.C) {
	svcID1 := ServiceID{Name: "svc1", Namespace: "default"}
	svcID2 := ServiceID{Name: "svc2", Namespace: "default"}

	endpoints := Endpoints{
		BackendIPs: map[string]bool{
			"3.3.3.3": true,
		},
		Ports: map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
			"port": {
				Protocol: loadbalancer.TCP,
				Port:     80,
			},
		},
	}

	cache := NewServiceCache()
	cache.services = map[ServiceID]*Service{
		svcID1: &Service{
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
		svcID2: &Service{
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
		"1.1.1.1:10/TCP": struct{}{},
		"1.1.1.1:20/TCP": struct{}{},
		"2.2.2.2:20/UDP": struct{}{},
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

	// Reinserting the endpoints should re-match with the still existing service
	svcCache.UpdateEndpoints(k8sEndpoints)
	c.Assert(testutils.WaitUntil(func() bool {
		event := <-svcCache.Events
		c.Assert(event.Action, check.Equals, UpdateService)
		c.Assert(event.ID, check.Equals, svcID)
		return true
	}, 2*time.Second), check.IsNil)

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
