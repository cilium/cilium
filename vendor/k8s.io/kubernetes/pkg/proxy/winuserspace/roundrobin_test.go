/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package winuserspace

import (
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/proxy"
)

func TestValidateWorks(t *testing.T) {
	if isValidEndpoint(&hostPortPair{}) {
		t.Errorf("Didn't fail for empty set")
	}
	if isValidEndpoint(&hostPortPair{host: "foobar"}) {
		t.Errorf("Didn't fail with invalid port")
	}
	if isValidEndpoint(&hostPortPair{host: "foobar", port: -1}) {
		t.Errorf("Didn't fail with a negative port")
	}
	if !isValidEndpoint(&hostPortPair{host: "foobar", port: 8080}) {
		t.Errorf("Failed a valid config.")
	}
}

func TestFilterWorks(t *testing.T) {
	endpoints := []hostPortPair{
		{host: "foobar", port: 1},
		{host: "foobar", port: 2},
		{host: "foobar", port: -1},
		{host: "foobar", port: 3},
		{host: "foobar", port: -2},
	}
	filtered := flattenValidEndpoints(endpoints)

	if len(filtered) != 3 {
		t.Errorf("Failed to filter to the correct size")
	}
	if filtered[0] != "foobar:1" {
		t.Errorf("Index zero is not foobar:1")
	}
	if filtered[1] != "foobar:2" {
		t.Errorf("Index one is not foobar:2")
	}
	if filtered[2] != "foobar:3" {
		t.Errorf("Index two is not foobar:3")
	}
}

func TestLoadBalanceFailsWithNoEndpoints(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "does-not-exist"}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil {
		t.Errorf("Didn't fail with non-existent service")
	}
	if len(endpoint) != 0 {
		t.Errorf("Got an endpoint")
	}
}

func expectEndpoint(t *testing.T, loadBalancer *LoadBalancerRR, service proxy.ServicePortName, expected string, netaddr net.Addr) {
	endpoint, err := loadBalancer.NextEndpoint(service, netaddr, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s, expected %s, failed with: %v", service, expected, err)
	}
	if endpoint != expected {
		t.Errorf("Didn't get expected endpoint for service %s client %v, expected %s, got: %s", service, netaddr, expected, endpoint)
	}
}

func expectEndpointWithSessionAffinityReset(t *testing.T, loadBalancer *LoadBalancerRR, service proxy.ServicePortName, expected string, netaddr net.Addr) {
	endpoint, err := loadBalancer.NextEndpoint(service, netaddr, true)
	if err != nil {
		t.Errorf("Didn't find a service for %s, expected %s, failed with: %v", service, expected, err)
	}
	if endpoint != expected {
		t.Errorf("Didn't get expected endpoint for service %s client %v, expected %s, got: %s", service, netaddr, expected, endpoint)
	}
}

func TestLoadBalanceWorksWithSingleEndpoint(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "p"}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
	endpoints := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{{
			Addresses: []api.EndpointAddress{{IP: "endpoint1"}},
			Ports:     []api.EndpointPort{{Name: "p", Port: 40}},
		}},
	}
	loadBalancer.OnEndpointsAdd(endpoints)
	expectEndpoint(t, loadBalancer, service, "endpoint1:40", nil)
	expectEndpoint(t, loadBalancer, service, "endpoint1:40", nil)
	expectEndpoint(t, loadBalancer, service, "endpoint1:40", nil)
	expectEndpoint(t, loadBalancer, service, "endpoint1:40", nil)
}

func stringsInSlice(haystack []string, needles ...string) bool {
	for _, needle := range needles {
		found := false
		for i := range haystack {
			if haystack[i] == needle {
				found = true
				break
			}
		}
		if found == false {
			return false
		}
	}
	return true
}

func TestLoadBalanceWorksWithMultipleEndpoints(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "p"}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
	endpoints := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{{
			Addresses: []api.EndpointAddress{{IP: "endpoint"}},
			Ports:     []api.EndpointPort{{Name: "p", Port: 1}, {Name: "p", Port: 2}, {Name: "p", Port: 3}},
		}},
	}
	loadBalancer.OnEndpointsAdd(endpoints)

	shuffledEndpoints := loadBalancer.services[service].endpoints
	if !stringsInSlice(shuffledEndpoints, "endpoint:1", "endpoint:2", "endpoint:3") {
		t.Errorf("did not find expected endpoints: %v", shuffledEndpoints)
	}
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], nil)
}

func TestLoadBalanceWorksWithMultipleEndpointsMultiplePorts(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "p"}
	serviceQ := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "q"}
	endpoint, err := loadBalancer.NextEndpoint(serviceP, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
	endpoints := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint1"}, {IP: "endpoint2"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 1}, {Name: "q", Port: 2}},
			},
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint3"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 3}, {Name: "q", Port: 4}},
			},
		},
	}
	loadBalancer.OnEndpointsAdd(endpoints)

	shuffledEndpoints := loadBalancer.services[serviceP].endpoints
	if !stringsInSlice(shuffledEndpoints, "endpoint1:1", "endpoint2:1", "endpoint3:3") {
		t.Errorf("did not find expected endpoints: %v", shuffledEndpoints)
	}
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[0], nil)

	shuffledEndpoints = loadBalancer.services[serviceQ].endpoints
	if !stringsInSlice(shuffledEndpoints, "endpoint1:2", "endpoint2:2", "endpoint3:4") {
		t.Errorf("did not find expected endpoints: %v", shuffledEndpoints)
	}
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[0], nil)
}

func TestLoadBalanceWorksWithMultipleEndpointsAndUpdates(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	serviceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "p"}
	serviceQ := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "q"}
	endpoint, err := loadBalancer.NextEndpoint(serviceP, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
	endpointsv1 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint1"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 1}, {Name: "q", Port: 10}},
			},
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint2"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 2}, {Name: "q", Port: 20}},
			},
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint3"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 3}, {Name: "q", Port: 30}},
			},
		},
	}
	loadBalancer.OnEndpointsAdd(endpointsv1)

	shuffledEndpoints := loadBalancer.services[serviceP].endpoints
	if !stringsInSlice(shuffledEndpoints, "endpoint1:1", "endpoint2:2", "endpoint3:3") {
		t.Errorf("did not find expected endpoints: %v", shuffledEndpoints)
	}
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[0], nil)

	shuffledEndpoints = loadBalancer.services[serviceQ].endpoints
	if !stringsInSlice(shuffledEndpoints, "endpoint1:10", "endpoint2:20", "endpoint3:30") {
		t.Errorf("did not find expected endpoints: %v", shuffledEndpoints)
	}
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[0], nil)

	// Then update the configuration with one fewer endpoints, make sure
	// we start in the beginning again
	endpointsv2 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint4"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 4}, {Name: "q", Port: 40}},
			},
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint5"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 5}, {Name: "q", Port: 50}},
			},
		},
	}
	loadBalancer.OnEndpointsUpdate(endpointsv1, endpointsv2)

	shuffledEndpoints = loadBalancer.services[serviceP].endpoints
	if !stringsInSlice(shuffledEndpoints, "endpoint4:4", "endpoint5:5") {
		t.Errorf("did not find expected endpoints: %v", shuffledEndpoints)
	}
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceP, shuffledEndpoints[1], nil)

	shuffledEndpoints = loadBalancer.services[serviceQ].endpoints
	if !stringsInSlice(shuffledEndpoints, "endpoint4:40", "endpoint5:50") {
		t.Errorf("did not find expected endpoints: %v", shuffledEndpoints)
	}
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, serviceQ, shuffledEndpoints[1], nil)

	// Clear endpoints
	endpointsv3 := &api.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: serviceP.Name, Namespace: serviceP.Namespace}, Subsets: nil}
	loadBalancer.OnEndpointsUpdate(endpointsv2, endpointsv3)

	endpoint, err = loadBalancer.NextEndpoint(serviceP, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
}

func TestLoadBalanceWorksWithServiceRemoval(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	fooServiceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: "p"}
	barServiceP := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "bar"}, Port: "p"}
	endpoint, err := loadBalancer.NextEndpoint(fooServiceP, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
	endpoints1 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: fooServiceP.Name, Namespace: fooServiceP.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint1"}, {IP: "endpoint2"}, {IP: "endpoint3"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 123}},
			},
		},
	}
	endpoints2 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: barServiceP.Name, Namespace: barServiceP.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint4"}, {IP: "endpoint5"}, {IP: "endpoint6"}},
				Ports:     []api.EndpointPort{{Name: "p", Port: 456}},
			},
		},
	}
	loadBalancer.OnEndpointsAdd(endpoints1)
	loadBalancer.OnEndpointsAdd(endpoints2)
	shuffledFooEndpoints := loadBalancer.services[fooServiceP].endpoints
	expectEndpoint(t, loadBalancer, fooServiceP, shuffledFooEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, fooServiceP, shuffledFooEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, fooServiceP, shuffledFooEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, fooServiceP, shuffledFooEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, fooServiceP, shuffledFooEndpoints[1], nil)

	shuffledBarEndpoints := loadBalancer.services[barServiceP].endpoints
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[1], nil)

	// Then update the configuration by removing foo
	loadBalancer.OnEndpointsDelete(endpoints1)
	endpoint, err = loadBalancer.NextEndpoint(fooServiceP, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}

	// but bar is still there, and we continue RR from where we left off.
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[2], nil)
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[0], nil)
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[1], nil)
	expectEndpoint(t, loadBalancer, barServiceP, shuffledBarEndpoints[2], nil)
}

func TestStickyLoadBalanceWorksWithNewServiceCalledFirst(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: ""}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}

	// Call NewService() before OnEndpointsUpdate()
	loadBalancer.NewService(service, api.ServiceAffinityClientIP, int(api.DefaultClientIPServiceAffinitySeconds))
	endpoints := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{Addresses: []api.EndpointAddress{{IP: "endpoint1"}}, Ports: []api.EndpointPort{{Port: 1}}},
			{Addresses: []api.EndpointAddress{{IP: "endpoint2"}}, Ports: []api.EndpointPort{{Port: 2}}},
			{Addresses: []api.EndpointAddress{{IP: "endpoint3"}}, Ports: []api.EndpointPort{{Port: 3}}},
		},
	}
	loadBalancer.OnEndpointsAdd(endpoints)

	client1 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	client2 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}
	client3 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 0}

	ep1, err := loadBalancer.NextEndpoint(service, client1, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}
	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep1, client1)

	ep2, err := loadBalancer.NextEndpoint(service, client2, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep2, client2)

	ep3, err := loadBalancer.NextEndpoint(service, client3, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}
	expectEndpoint(t, loadBalancer, service, ep3, client3)
	expectEndpoint(t, loadBalancer, service, ep3, client3)
	expectEndpoint(t, loadBalancer, service, ep3, client3)

	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep3, client3)
	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep3, client3)
}

func TestStickyLoadBalanceWorksWithNewServiceCalledSecond(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: ""}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}

	// Call OnEndpointsUpdate() before NewService()
	endpoints := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{Addresses: []api.EndpointAddress{{IP: "endpoint1"}}, Ports: []api.EndpointPort{{Port: 1}}},
			{Addresses: []api.EndpointAddress{{IP: "endpoint2"}}, Ports: []api.EndpointPort{{Port: 2}}},
		},
	}
	loadBalancer.OnEndpointsAdd(endpoints)
	loadBalancer.NewService(service, api.ServiceAffinityClientIP, int(api.DefaultClientIPServiceAffinitySeconds))

	client1 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	client2 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}
	client3 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 0}

	ep1, err := loadBalancer.NextEndpoint(service, client1, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}
	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep1, client1)

	ep2, err := loadBalancer.NextEndpoint(service, client2, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep2, client2)

	ep3, err := loadBalancer.NextEndpoint(service, client3, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}
	expectEndpoint(t, loadBalancer, service, ep3, client3)
	expectEndpoint(t, loadBalancer, service, ep3, client3)
	expectEndpoint(t, loadBalancer, service, ep3, client3)

	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep3, client3)
	expectEndpoint(t, loadBalancer, service, ep1, client1)
	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpoint(t, loadBalancer, service, ep3, client3)
}

func TestStickyLoadBalanaceWorksWithMultipleEndpointsRemoveOne(t *testing.T) {
	client1 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	client2 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}
	client3 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 0}
	client4 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 4), Port: 0}
	client5 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 5), Port: 0}
	client6 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 6), Port: 0}
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: ""}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}

	loadBalancer.NewService(service, api.ServiceAffinityClientIP, int(api.DefaultClientIPServiceAffinitySeconds))
	endpointsv1 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint"}},
				Ports:     []api.EndpointPort{{Port: 1}, {Port: 2}, {Port: 3}},
			},
		},
	}
	loadBalancer.OnEndpointsAdd(endpointsv1)
	shuffledEndpoints := loadBalancer.services[service].endpoints
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	client1Endpoint := shuffledEndpoints[0]
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)
	client2Endpoint := shuffledEndpoints[1]
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[2], client3)
	client3Endpoint := shuffledEndpoints[2]

	endpointsv2 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint"}},
				Ports:     []api.EndpointPort{{Port: 1}, {Port: 2}},
			},
		},
	}
	loadBalancer.OnEndpointsUpdate(endpointsv1, endpointsv2)
	shuffledEndpoints = loadBalancer.services[service].endpoints
	if client1Endpoint == "endpoint:3" {
		client1Endpoint = shuffledEndpoints[0]
	} else if client2Endpoint == "endpoint:3" {
		client2Endpoint = shuffledEndpoints[0]
	} else if client3Endpoint == "endpoint:3" {
		client3Endpoint = shuffledEndpoints[0]
	}
	expectEndpoint(t, loadBalancer, service, client1Endpoint, client1)
	expectEndpoint(t, loadBalancer, service, client2Endpoint, client2)
	expectEndpoint(t, loadBalancer, service, client3Endpoint, client3)

	endpointsv3 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint"}},
				Ports:     []api.EndpointPort{{Port: 1}, {Port: 2}, {Port: 4}},
			},
		},
	}
	loadBalancer.OnEndpointsUpdate(endpointsv2, endpointsv3)
	shuffledEndpoints = loadBalancer.services[service].endpoints
	expectEndpoint(t, loadBalancer, service, client1Endpoint, client1)
	expectEndpoint(t, loadBalancer, service, client2Endpoint, client2)
	expectEndpoint(t, loadBalancer, service, client3Endpoint, client3)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client4)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client5)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[2], client6)
}

func TestStickyLoadBalanceWorksWithMultipleEndpointsAndUpdates(t *testing.T) {
	client1 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	client2 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}
	client3 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 0}
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: ""}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}

	loadBalancer.NewService(service, api.ServiceAffinityClientIP, int(api.DefaultClientIPServiceAffinitySeconds))
	endpointsv1 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint"}},
				Ports:     []api.EndpointPort{{Port: 1}, {Port: 2}, {Port: 3}},
			},
		},
	}
	loadBalancer.OnEndpointsAdd(endpointsv1)
	shuffledEndpoints := loadBalancer.services[service].endpoints
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[2], client3)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)
	// Then update the configuration with one fewer endpoints, make sure
	// we start in the beginning again
	endpointsv2 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint"}},
				Ports:     []api.EndpointPort{{Port: 4}, {Port: 5}},
			},
		},
	}
	loadBalancer.OnEndpointsUpdate(endpointsv1, endpointsv2)
	shuffledEndpoints = loadBalancer.services[service].endpoints
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, service, shuffledEndpoints[1], client2)

	// Clear endpoints
	endpointsv3 := &api.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace}, Subsets: nil}
	loadBalancer.OnEndpointsUpdate(endpointsv2, endpointsv3)

	endpoint, err = loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
}

func TestStickyLoadBalanceWorksWithServiceRemoval(t *testing.T) {
	client1 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	client2 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}
	client3 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 0}
	loadBalancer := NewLoadBalancerRR()
	fooService := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: ""}
	endpoint, err := loadBalancer.NextEndpoint(fooService, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}
	loadBalancer.NewService(fooService, api.ServiceAffinityClientIP, int(api.DefaultClientIPServiceAffinitySeconds))
	endpoints1 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: fooService.Name, Namespace: fooService.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint"}},
				Ports:     []api.EndpointPort{{Port: 1}, {Port: 2}, {Port: 3}},
			},
		},
	}
	barService := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "bar"}, Port: ""}
	loadBalancer.NewService(barService, api.ServiceAffinityClientIP, int(api.DefaultClientIPServiceAffinitySeconds))
	endpoints2 := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: barService.Name, Namespace: barService.Namespace},
		Subsets: []api.EndpointSubset{
			{
				Addresses: []api.EndpointAddress{{IP: "endpoint"}},
				Ports:     []api.EndpointPort{{Port: 4}, {Port: 5}},
			},
		},
	}
	loadBalancer.OnEndpointsAdd(endpoints1)
	loadBalancer.OnEndpointsAdd(endpoints2)

	shuffledFooEndpoints := loadBalancer.services[fooService].endpoints
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[2], client3)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[2], client3)
	expectEndpoint(t, loadBalancer, fooService, shuffledFooEndpoints[2], client3)

	shuffledBarEndpoints := loadBalancer.services[barService].endpoints
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[1], client2)

	// Then update the configuration by removing foo
	loadBalancer.OnEndpointsDelete(endpoints1)
	endpoint, err = loadBalancer.NextEndpoint(fooService, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}

	// but bar is still there, and we continue RR from where we left off.
	shuffledBarEndpoints = loadBalancer.services[barService].endpoints
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[1], client2)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[0], client1)
	expectEndpoint(t, loadBalancer, barService, shuffledBarEndpoints[0], client1)
}

func TestStickyLoadBalanceWorksWithEndpointFails(t *testing.T) {
	loadBalancer := NewLoadBalancerRR()
	service := proxy.ServicePortName{NamespacedName: types.NamespacedName{Namespace: "testnamespace", Name: "foo"}, Port: ""}
	endpoint, err := loadBalancer.NextEndpoint(service, nil, false)
	if err == nil || len(endpoint) != 0 {
		t.Errorf("Didn't fail with non-existent service")
	}

	// Call NewService() before OnEndpointsUpdate()
	loadBalancer.NewService(service, api.ServiceAffinityClientIP, int(api.DefaultClientIPServiceAffinitySeconds))
	endpoints := &api.Endpoints{
		ObjectMeta: metav1.ObjectMeta{Name: service.Name, Namespace: service.Namespace},
		Subsets: []api.EndpointSubset{
			{Addresses: []api.EndpointAddress{{IP: "endpoint1"}}, Ports: []api.EndpointPort{{Port: 1}}},
			{Addresses: []api.EndpointAddress{{IP: "endpoint2"}}, Ports: []api.EndpointPort{{Port: 2}}},
			{Addresses: []api.EndpointAddress{{IP: "endpoint3"}}, Ports: []api.EndpointPort{{Port: 3}}},
		},
	}
	loadBalancer.OnEndpointsAdd(endpoints)

	client1 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	client2 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 0}
	client3 := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 0}

	ep1, err := loadBalancer.NextEndpoint(service, client1, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}

	ep2, err := loadBalancer.NextEndpoint(service, client2, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}

	ep3, err := loadBalancer.NextEndpoint(service, client3, false)
	if err != nil {
		t.Errorf("Didn't find a service for %s: %v", service, err)
	}

	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep1, client1)
	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep2, client1)
	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep3, client1)

	expectEndpoint(t, loadBalancer, service, ep2, client2)
	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep1, client2)
	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep2, client3)
	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep3, client1)
	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep1, client2)
	expectEndpointWithSessionAffinityReset(t, loadBalancer, service, ep2, client3)
}
