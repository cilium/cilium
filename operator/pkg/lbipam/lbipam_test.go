// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_testing "k8s.io/client-go/testing"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestConflictResolution tests that, upon initialization, LB IPAM will detect conflicts between pools,
// internally disables one of the pools, and notifies the user via a status update.
// Next, we update the conflicting pool to remove the offending range, this should re-enable the pool.
func TestConflictResolution(t *testing.T) {
	poolB := mkPool(poolBUID, "pool-b", []string{"10.0.10.0/24", "FF::0/48"})
	poolB.CreationTimestamp = meta_v1.Date(2022, 10, 16, 13, 30, 00, 0, time.UTC)
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
		poolB,
	}, true, false, nil)

	await := fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "patch" {
			return false
		}

		pool := fixture.PatchedPool(action)

		if pool.Name != "pool-b" {
			return false
		}

		if !isPoolConflicting(pool) {
			return false
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Pool B has not been marked conflicting")
	}

	// All ranges of a conflicting pool must be disabled
	poolBRanges, _ := fixture.lbIPAM.rangesStore.GetRangesForPool("pool-b")
	for _, r := range poolBRanges {
		if !r.internallyDisabled {
			t.Fatalf("Range '%s' from pool B hasn't been disabled", ipNetStr(r.allocRange.CIDR()))
		}
	}

	// Phase 2, resolving the conflict

	await = fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "patch" {
			return false
		}

		pool := fixture.PatchedPool(action)

		if pool.Name != "pool-b" {
			return false
		}

		if isPoolConflicting(pool) {
			return false
		}

		return true
	}, time.Second)

	poolB, err := fixture.poolClient.Get(context.Background(), "pool-b", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(poolB)
	}

	// Remove the conflicting range
	poolB.Spec.Cidrs = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		{
			Cidr: cilium_api_v2alpha1.IPv4orIPv6CIDR("FF::0/48"),
		},
	}

	_, err = fixture.poolClient.Update(context.Background(), poolB, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Pool b has not de-conflicted")
	}
}

// TestPoolInternalConflict tests that LB-IPAM can detect when two ranges in the same pool have overlapping CIDRs,
// mark the pool as `conflicting` and disables all ranges. Then de-conflict the pool by removing one of the ranges
// after which the pool should be no longer be marked conflicting.
func TestPoolInternalConflict(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24", "10.0.10.64/28"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, false, nil)

	await := fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "patch" {
			return false
		}

		pool := fixture.PatchedPool(action)

		if !isPoolConflicting(pool) {
			return false
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected pool to be marked conflicting")
	}

	await = fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "patch" {
			return false
		}

		pool := fixture.PatchedPool(action)

		if isPoolConflicting(pool) {
			return false
		}

		return true
	}, 2*time.Second)

	pool, err := fixture.poolClient.Get(context.Background(), "pool-a", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	pool.Spec.Cidrs = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		{
			Cidr: "10.0.10.0/24",
		},
	}

	_, err = fixture.poolClient.Update(context.Background(), pool, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected pool to be un-marked conflicting")
	}
}

// TestAllocHappyPath tests that an existing service will first get an IPv4 address assigned, then when they request
// an IPv6 instead, the IPv4 is freed and an IPv6 is allocated for them.
func TestAllocHappyPath(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24", "FF::0/48"}),
	}, true, true, nil)

	// Initially request only an IPv4
	policy := slim_core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []slim_core_v1.IPFamily{
					slim_core_v1.IPv4Protocol,
				},
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action.(k8s_testing.PatchAction))

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Error("Expected service to receive a IPv4 address")
			return true
		}

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to receive exactly one condition")
			return true
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Unexpected condition type assigned to service")
			return true
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
			t.Error("Unexpected condition status assigned to service")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service to be updated")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	svc, err := fixture.svcClient.Services("default").Get(context.Background(), "service-a", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Switch to requesting an IPv6 address
	svc.Spec.IPFamilies = []slim_core_v1.IPFamily{
		slim_core_v1.IPv6Protocol,
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action.(k8s_testing.PatchAction))

		// The second update allocates the new IPv6
		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() != nil {
			t.Error("Expected service to receive a IPv6 address")
			return true
		}

		return true
	}, time.Second)

	_, err = fixture.svcClient.Services("default").Update(context.Background(), svc, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update after update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	// Allow time for additional events to fire
	time.Sleep(100 * time.Millisecond)

	svc, err = fixture.svcClient.Services("default").Get(context.Background(), "service-a", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Switch back to requesting an IPv4 address
	svc.Spec.IPFamilies = []slim_core_v1.IPFamily{
		slim_core_v1.IPv4Protocol,
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action.(k8s_testing.PatchAction))

		// The second update allocates the new IPv4
		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Error("Expected service to receive a IPv4 address")
			return true
		}

		return true
	}, time.Second)

	_, err = fixture.svcClient.Services("default").Update(context.Background(), svc, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update after update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}
}

// TestServiceDelete tests the service deletion logic. It makes sure that the IP that was assigned to the service is
// released after the service is deleted so it can be re-assigned.
func TestServiceDelete(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type: slim_core_v1.ServiceTypeLoadBalancer,
				IPFamilies: []slim_core_v1.IPFamily{
					slim_core_v1.IPv4Protocol,
				},
			},
		},
	)

	var svcIP string

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Error("Expected service to receive a IPv4 address")
			return true
		}

		svcIP = svc.Status.LoadBalancer.Ingress[0].IP

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status to be updated")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	if !fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP(svcIP)) {
		t.Fatal("Service IP hasn't been allocated")
	}

	err := fixture.svcClient.Services("default").Delete(context.Background(), "service-a", meta_v1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	if fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP(svcIP)) {
		t.Fatal("Service IP hasn't been released")
	}
}

// TestReallocOnInit tests the edge case where an existing service has an IP assigned for which there is no IP Pool.
// LB IPAM should take the unknown IP away and allocate a new and valid IP. This scenario can happen when a service
// passes ownership from on controller to another or when a pool is deleted while the operator is down.
func TestReallocOnInit(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true, nil)

	// Initially request only an IPv4
	policy := slim_core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []slim_core_v1.IPFamily{
					slim_core_v1.IPv4Protocol,
				},
			},
			Status: slim_core_v1.ServiceStatus{
				LoadBalancer: slim_core_v1.LoadBalancerStatus{
					Ingress: []slim_core_v1.LoadBalancerIngress{
						{
							IP: "192.168.1.12",
						},
					},
				},
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Error("Expected service to receive a IPv4 address")
			return true
		}

		if svc.Status.LoadBalancer.Ingress[0].IP == "192.168.1.12" {
			t.Error("Expected ingress IP to not be the initial, bad IP")
			return true
		}

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to receive exactly one condition")
			return true
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Expected second condition to be svc-satisfied:true")
			return true
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
			t.Error("Expected second condition to be svc-satisfied:true")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service to be updated")
	}
}

// TestAllocOnInit tests that on init, ingress IPs on services which match configured pools are imported
// and marked as allocated. This is crucial when restarting the operator in a running cluster.
func TestAllocOnInit(t *testing.T) {
	initDone := make(chan struct{})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true, func() {
		close(initDone)
	})

	policy := slim_core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []slim_core_v1.IPFamily{
					slim_core_v1.IPv4Protocol,
				},
			},
			Status: slim_core_v1.ServiceStatus{
				LoadBalancer: slim_core_v1.LoadBalancerStatus{
					Ingress: []slim_core_v1.LoadBalancerIngress{
						{
							IP: "10.0.10.123",
						},
					},
				},
			},
		},
	)
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-b",
				Namespace: "default",
				UID:       serviceBUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.10.124",
			},
			Status: slim_core_v1.ServiceStatus{
				LoadBalancer: slim_core_v1.LoadBalancerStatus{
					Ingress: []slim_core_v1.LoadBalancerIngress{
						{
							IP: "10.0.10.124",
						},
					},
				},
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		t.Error("No service updates expected")

		return false
	}, 100*time.Millisecond)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	<-initDone

	await.Block()

	if !fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP("10.0.10.123")) {
		t.Fatal("Expected the imported IP to be allocated")
	}

	if !fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP("10.0.10.124")) {
		t.Fatal("Expected the imported IP to be allocated")
	}
}

// TestPoolSelector tests that an IP Pool will only allocate IPs to services which match its service selector.
// The selector in this case is a very simple label.
func TestPoolSelectorBasic(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	selector := slim_meta_v1.LabelSelector{
		MatchLabels: map[string]string{
			"color": "red",
		},
	}
	poolA.Spec.ServiceSelector = &selector

	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "red-service" {
			t.Error("Expected update from 'red-service'")
			return true
		}

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Error("Expected service to receive a IPv4 address")
			return true
		}

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to receive exactly one condition")
			return true
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Expected condition to be svc-satisfied:true")
			return true
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
			t.Error("Expected condition to be svc-satisfied:true")
			return true
		}

		return true
	}, time.Second)

	policy := slim_core_v1.IPFamilyPolicySingleStack
	matchingService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name: "red-service",
			UID:  serviceAUID,
			Labels: map[string]string{
				"color": "red",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err := fixture.svcClient.Services("default").Create(context.Background(), matchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "blue-service" {
			return false
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to not receive any ingress IPs")
			return true
		}

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to receive exactly one condition")
			return true
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Expected condition to be svc-satisfied:false")
			return true
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
			t.Error("Expected condition to be svc-satisfied:false")
			return true
		}

		return true
	}, time.Second)

	nonMatchingService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name: "blue-service",
			UID:  serviceBUID,
			Labels: map[string]string{
				"color": "blue",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err = fixture.svcClient.Services("default").Create(context.Background(), nonMatchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestPoolSelectorNamespace tests that an IP Pool with a 'io.kubernetes.service.namespace' selector will only
// assign IPs to services in the given namespace.
func TestPoolSelectorNamespace(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	selector := slim_meta_v1.LabelSelector{
		MatchLabels: map[string]string{
			"io.kubernetes.service.namespace": "tenant-one",
		},
	}
	poolA.Spec.ServiceSelector = &selector

	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "red-service" {
			t.Error("Expected update from 'red-service'")
			return true
		}

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Error("Expected service to receive a IPv4 address")
			return true
		}

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to receive exactly one condition")
			return true
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Expected condition to be svc-satisfied:true")
			return true
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
			t.Error("Expected condition to be svc-satisfied:true")
			return true
		}

		return true
	}, time.Second)

	policy := slim_core_v1.IPFamilyPolicySingleStack
	matchingService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "red-service",
			Namespace: "tenant-one",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err := fixture.svcClient.Services("tenant-one").Create(context.Background(), matchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "blue-service" {
			return false
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to not receive any ingress IPs")
		}

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to receive exactly one condition")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Expected condition to be svc-satisfied:false")
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
			t.Error("Expected condition to be svc-satisfied:false")
		}

		return true
	}, time.Second)

	nonMatchingService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "blue-service",
			Namespace: "tenant-two",
			UID:       serviceBUID,
			Labels: map[string]string{
				// Setting the same label in an attempt to escalate privileges doesn't work
				"io.kubernetes.service.namespace": "tenant-one",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err = fixture.svcClient.Services("tenant-two").Create(context.Background(), nonMatchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestChangeServiceType tests that we don't handle non-LB services, then we update the type and check that we start
// handling the service, then switch the type again and verify that we release the allocated IP.
func TestChangeServiceType(t *testing.T) {
	initDone := make(chan struct{})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true, func() {
		close(initDone)
	})

	// This existing ClusterIP service should be ignored
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type: slim_core_v1.ServiceTypeClusterIP,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		t.Error("No service updates expected")

		return false
	}, 100*time.Millisecond)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	<-initDone

	await.Block()

	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	var assignedIP string

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Error("Expected service to receive a IPv4 address")
			return true
		}

		assignedIP = svc.Status.LoadBalancer.Ingress[0].IP

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to receive exactly one condition")
			return true
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Expected condition to be svc-satisfied:true")
			return true
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
			t.Error("Expected condition to be svc-satisfied:true")
			return true
		}

		return true
	}, time.Second)

	updatedService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}

	_, err := fixture.svcClient.Services("default").Update(context.Background(), updatedService, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to have no ingress IPs")
			return true
		}

		if len(svc.Status.Conditions) != 0 {
			t.Error("Expected service to have no conditions")
			return true
		}

		return true
	}, time.Second)

	updatedService = &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeNodePort,
		},
	}

	_, err = fixture.svcClient.Services("default").Update(context.Background(), updatedService, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	if fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP(assignedIP)) {
		t.Fatal("Expected assigned IP to be released")
	}
}

// TestRangesFull tests the behavior when all eligible ranges are full.
func TestRangesFull(t *testing.T) {
	initDone := make(chan struct{})
	// A single /32 can't be used to allocate since we always reserve 2 IPs,
	// the network and broadcast address, which in the case of a /32 means it is always full.
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.123/32", "FF::123/128"}),
	}, true, true, func() {
		close(initDone)
	})

	policy := slim_core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []slim_core_v1.IPFamily{
					slim_core_v1.IPv4Protocol,
				},
			},
		},
	)
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-b",
				Namespace: "default",
				UID:       serviceBUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []slim_core_v1.IPFamily{
					slim_core_v1.IPv6Protocol,
				},
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "service-a" {
			if len(svc.Status.LoadBalancer.Ingress) != 0 {
				t.Error("Expected service to have no ingress IPs")
				return true
			}

			if len(svc.Status.Conditions) != 1 {
				t.Error("Expected service to have one conditions")
				return true
			}

			if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
				t.Error("Expected condition to be svc-satisfied:false")
				return true
			}

			if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
				t.Error("Expected condition to be svc-satisfied:false")
				return true
			}

			if svc.Status.Conditions[0].Reason != "out_of_ips" {
				t.Error("Expected condition reason to be out of IPs")
				return true
			}

			return false
		}

		if svc.Name != "service-b" {

			if len(svc.Status.LoadBalancer.Ingress) != 0 {
				t.Error("Expected service to have no ingress IPs")
				return true
			}

			if len(svc.Status.Conditions) != 1 {
				t.Error("Expected service to have one conditions")
				return true
			}

			if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
				t.Error("Expected condition to be svc-satisfied:false")
				return true
			}

			if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
				t.Error("Expected condition to be svc-satisfied:false")
				return true
			}

			if svc.Status.Conditions[0].Reason != "out_of_ips" {
				t.Error("Expected condition reason to be out of IPs")
				return true
			}
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	<-initDone

	if await.Block() {
		t.Fatal("Expected two service updates")
	}
}

// TestRequestIPs tests that we can request specific IPs
func TestRequestIPs(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.10.20",
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if svc.Status.LoadBalancer.Ingress[0].IP != "10.0.10.20" {
			t.Error("Expected service to receive IP '10.0.10.20'")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "service-b" {
			t.Error("Expected status update for service-b")
			return true
		}

		if len(svc.Status.LoadBalancer.Ingress) != 3 {
			t.Error("Expected service to receive exactly three ingress IPs")
			return true
		}

		first := false
		second := false
		third := false

		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			switch ingress.IP {
			case "10.0.10.21":
				first = true
			case "10.0.10.22":
				second = true
			case "10.0.10.23":
				third = true
			default:
				t.Error("Unexpected ingress IP")
				return true
			}
		}

		if !first {
			t.Error("Expected service to receive IP '10.0.10.21'")
			return true
		}

		if !second {
			t.Error("Expected service to receive IP '10.0.10.22'")
			return true
		}

		if !third {
			t.Error("Expected service to receive IP '10.0.10.23'")
			return true
		}

		return true
	}, time.Second)

	serviceB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
			Annotations: map[string]string{
				ciliumSvcLBIPSAnnotation: "10.0.10.22,10.0.10.23",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.10.21",
		},
	}

	_, err := fixture.svcClient.Services("default").Create(context.Background(), serviceB, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "service-c" {
			t.Error("Expected status update for service-b")
			return true
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to receive no ingress IPs")
			return true
		}

		if len(svc.Status.Conditions) != 1 {
			t.Error("Expected service to have one conditions")
			return true
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Error("Expected condition to be request-valid:false")
			return true
		}

		if svc.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
			t.Error("Expected condition to be request-valid:false")
			return true
		}

		if svc.Status.Conditions[0].Reason != "already_allocated" {
			t.Error("Expected condition reason to be 'already_allocated'")
			return true
		}

		return true
	}, time.Second)

	// request an already allocated IP
	serviceC := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-c",
			Namespace: "default",
			UID:       serviceCUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.10.21",
		},
	}

	_, err = fixture.svcClient.Services("default").Create(context.Background(), serviceC, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestAddPool tests that adding a new pool will satisfy services.
func TestAddPool(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.20.10",
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to receive no ingress IPs")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if svc.Status.LoadBalancer.Ingress[0].IP != "10.0.20.10" {
			t.Error("Expected service to receive IP '10.0.20.10'")
			return true
		}

		return true
	}, time.Second)

	twentyPool := mkPool(poolBUID, "pool-b", []string{"10.0.20.0/24"})
	_, err := fixture.poolClient.Create(context.Background(), twentyPool, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestAddRange tests adding a range to a pool will satisfy services which have not been able to get an IP
func TestAddRange(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.20.10",
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to receive no ingress IPs")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	poolA.Spec.Cidrs = append(poolA.Spec.Cidrs, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		Cidr: "10.0.20.0/24",
	})

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if svc.Status.LoadBalancer.Ingress[0].IP != "10.0.20.10" {
			t.Error("Expected service to receive IP '10.0.20.10'")
			return true
		}

		return true
	}, time.Second)

	_, err := fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestDisablePool tests that disabling a pool will not remove existing allocations but will stop new allocations.
// Then re-enable the pool and see that the pool resumes allocating IPs
func TestDisablePool(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type: slim_core_v1.ServiceTypeLoadBalancer,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		return true
	}, 500*time.Millisecond)

	poolA.Spec.Disabled = true

	_, err := fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !await.Block() {
		t.Fatal("Unexpected service status update")
	}

	if !fixture.lbIPAM.rangesStore.ranges[0].externallyDisabled {
		t.Fatal("The range has not been externally disabled")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "service-b" {
			t.Error("Expected service status update to occur on service-b")
			return true
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to receive no ingress IPs")
			return true
		}

		return true
	}, time.Second)

	serviceB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}

	_, err = fixture.svcClient.Services("default").Create(context.Background(), serviceB, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if svc.Name != "service-b" {
			return false
		}

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			return false
		}

		return true
	}, time.Second)

	poolA.Spec.Disabled = false

	_, err = fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestPoolDelete tests that when a pool is deleted, all of the IPs from that pool are released and that any effected
// services get a new IP from another pool.
func TestPoolDelete(t *testing.T) {
	initDone := make(chan struct{})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
		mkPool(poolBUID, "pool-b", []string{"10.0.20.0/24"}),
	}, true, true, func() {
		close(initDone)
	})

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type: slim_core_v1.ServiceTypeLoadBalancer,
			},
		},
	)

	var allocPool string

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if strings.HasPrefix(svc.Status.LoadBalancer.Ingress[0].IP, "10.0.10") {
			allocPool = "pool-a"
		} else {
			allocPool = "pool-b"
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	<-initDone

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if strings.HasPrefix(svc.Status.LoadBalancer.Ingress[0].IP, "10.0.10") {
			if allocPool == "pool-a" {
				t.Error("New IP was allocated from deleted pool")
				return true
			}
		} else {
			if allocPool == "pool-b" {
				t.Error("New IP was allocated from deleted pool")
				return true
			}
		}

		return true
	}, time.Second)

	err := fixture.poolClient.Delete(context.Background(), allocPool, meta_v1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestRangeDelete tests that when a range is deleted from a pool, all of the IPs from that range are released and
// that any effected services get a new IP from another range.
func TestRangeDelete(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type: slim_core_v1.ServiceTypeLoadBalancer,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		return true
	}, 500*time.Millisecond)

	// Add a new CIDR, this should not have any effect on the existing service.
	poolA.Spec.Cidrs = append(poolA.Spec.Cidrs, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		Cidr: "10.0.20.0/24",
	})
	_, err := fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !await.Block() {
		t.Fatal("Unexpected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		if !strings.HasPrefix(svc.Status.LoadBalancer.Ingress[0].IP, "10.0.20") {
			t.Error("Expected new ingress to be in the 10.0.20.0/24 range")
			return true
		}

		return true
	}, time.Second)

	// Remove the existing range, this should trigger the re-allocation of the existing service
	poolA.Spec.Cidrs = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		{
			Cidr: "10.0.20.0/24",
		},
	}
	_, err = fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestLBIPAM_serviceIPFamilyRequest tests that the correct IP address families are requested in the different
// combinations of service spec fields and enabled families in the cluster.
func TestLBIPAM_serviceIPFamilyRequest(t *testing.T) {
	type test struct {
		name              string
		IPv4Enabled       bool
		IPv6Enabled       bool
		svc               *slim_core_v1.Service
		wantIPv4Requested bool
		wantIPv6Requested bool
	}

	singleStack := slim_core_v1.IPFamilyPolicySingleStack
	preferDual := slim_core_v1.IPFamilyPolicyPreferDualStack
	requireDual := slim_core_v1.IPFamilyPolicyRequireDualStack

	tests := []test{
		{
			// If no policy is set, fall back to single stack. Only IPv4 enabled
			name: "No policy, No families, IPv4",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{},
			},
			IPv4Enabled:       true,
			wantIPv4Requested: true,
		},
		{
			// If no policy is set, fall back to single stack. Only IPv6 enabled
			name: "No policy, No families, IPv6",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{},
			},
			IPv6Enabled:       true,
			wantIPv6Requested: true,
		},
		{
			// If no policy is set, fall back to single stack. Prefer IPv4 over IPv6 in single stack
			name: "No policy, No families, IPv4/IPv6",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{},
			},
			IPv4Enabled:       true,
			IPv6Enabled:       true,
			wantIPv4Requested: true,
			wantIPv6Requested: false,
		},
		{
			// If no policy is set, fall back to single stack. Request IPv6, even if it is disabled.
			name: "No policy, IPv6 family, IPv4",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilies: []slim_core_v1.IPFamily{
						slim_core_v1.IPv6Protocol,
					},
				},
			},
			IPv4Enabled:       true,
			wantIPv6Requested: true,
		},
		{
			// If no policy is set, fall back to single stack. Request IPv4, even if it is disabled.
			name: "No policy, IPv4 family, IPv6",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilies: []slim_core_v1.IPFamily{
						slim_core_v1.IPv4Protocol,
					},
				},
			},
			IPv6Enabled:       true,
			wantIPv4Requested: true,
		},
		{
			// If no policy is set, fall back to single stack. Request the first family
			name: "No policy, IPv4/IPv6 family, No enabled",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilies: []slim_core_v1.IPFamily{
						slim_core_v1.IPv4Protocol,
						slim_core_v1.IPv6Protocol,
					},
				},
			},
			wantIPv4Requested: true,
		},
		{
			// If no policy is set, fall back to single stack. Request the first family
			name: "No policy, IPv4/IPv6 family, No enabled",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilies: []slim_core_v1.IPFamily{
						slim_core_v1.IPv6Protocol,
						slim_core_v1.IPv4Protocol,
					},
				},
			},
			wantIPv6Requested: true,
		},
		{
			// If single stack is explicitly set, and both are available, prefer IPv4
			name: "Single stack, No families, IPv6/IPv4",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilyPolicy: &singleStack,
				},
			},
			IPv4Enabled:       true,
			IPv6Enabled:       true,
			wantIPv4Requested: true,
		},
		{
			// If dual stack is requested, and available, request both
			name: "PreferDual, No families, IPv6/IPv4",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilyPolicy: &preferDual,
				},
			},
			IPv4Enabled:       true,
			IPv6Enabled:       true,
			wantIPv4Requested: true,
			wantIPv6Requested: true,
		},
		{
			// If dual stack is requested, and available, request family
			name: "PreferDual, IPv4 family, IPv6",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilyPolicy: &preferDual,
					IPFamilies: []slim_core_v1.IPFamily{
						slim_core_v1.IPv4Protocol,
					},
				},
			},
			IPv4Enabled:       false,
			IPv6Enabled:       true,
			wantIPv4Requested: false,
			wantIPv6Requested: false,
		},
		{
			// If dual stack is required, and available, request both
			name: "RequireDual, IPv4 family, IPv6",
			svc: &slim_core_v1.Service{
				Spec: slim_core_v1.ServiceSpec{
					IPFamilyPolicy: &requireDual,
					IPFamilies: []slim_core_v1.IPFamily{
						slim_core_v1.IPv4Protocol,
					},
				},
			},
			IPv4Enabled:       false,
			IPv6Enabled:       true,
			wantIPv4Requested: false,
			wantIPv6Requested: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipam := &LBIPAM{
				ipv4Enabled: tt.IPv4Enabled,
				ipv6Enabled: tt.IPv6Enabled,
			}
			gotIPv4Requested, gotIPv6Requested := ipam.serviceIPFamilyRequest(tt.svc)
			if gotIPv4Requested != tt.wantIPv4Requested {
				t.Errorf("LBIPAM.serviceIPFamilyRequest() gotIPv4Requested = %v, want %v", gotIPv4Requested, tt.wantIPv4Requested)
			}
			if gotIPv6Requested != tt.wantIPv6Requested {
				t.Errorf("LBIPAM.serviceIPFamilyRequest() gotIPv6Requested = %v, want %v", gotIPv6Requested, tt.wantIPv6Requested)
			}
		})
	}
}

// TestRemoveServiceLabel tests that changing/removing labels from a service that cause it to no longer match a pool
// will cause the allocated IPs from that pool to be released and removed from the service.
func TestRemoveServiceLabel(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	poolA.Spec.ServiceSelector = &slim_meta_v1.LabelSelector{
		MatchLabels: map[string]string{
			"color": "blue",
		},
	}
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	svc1 := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Labels: map[string]string{
				"color": "blue",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}

	fixture.coreCS.Tracker().Add(
		svc1,
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to receive exactly zero ingress IPs")
			return true
		}

		return true
	}, time.Second)

	svc1 = svc1.DeepCopy()
	svc1.Labels = map[string]string{
		"color": "green",
	}

	_, err := fixture.svcClient.Services(svc1.Namespace).Update(context.Background(), svc1, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestRequestIPWithMismatchedLabel tests that Requested IPs will not be allocated/assigned from a pool if the service
// doesn't match the selector on the pool.
func TestRequestIPWithMismatchedLabel(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	poolA.Spec.ServiceSelector = &slim_meta_v1.LabelSelector{
		MatchLabels: map[string]string{
			"color": "blue",
		},
	}
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
				Labels: map[string]string{
					"color": "red",
				},
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:           slim_core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.10.123",
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)
		if svc.Status.Conditions[0].Reason != "pool_selector_mismatch" {
			t.Error("Expected service to receive 'pool_selector_mismatch' condition")
		}

		return true
	}, 1*time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected status update of service")
	}
}

// TestRemoveRequestedIP tests that removing a requested IP from the spec will free the IP from the pool and remove
// it from the ingress list.
func TestRemoveRequestedIP(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	svc1 := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-ips": "10.0.10.124,10.0.10.125",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.10.123",
		},
	}

	fixture.coreCS.Tracker().Add(
		svc1,
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 3 {
			t.Error("Expected service to receive exactly three ingress IP")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 2 {
			t.Error("Expected service to receive exactly two ingress IPs")
			return true
		}

		return true
	}, time.Second)

	svc1 = svc1.DeepCopy()
	svc1.Annotations = map[string]string{
		"io.cilium/lb-ipam-ips": "10.0.10.124",
	}

	_, err := fixture.svcClient.Services(svc1.Namespace).Update(context.Background(), svc1, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	if !fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP("10.0.10.123")) {
		t.Fatal("Expected IP '10.0.10.123' to be allocated")
	}

	if !fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP("10.0.10.124")) {
		t.Fatal("Expected IP '10.0.10.124' to be allocated")
	}

	if fixture.lbIPAM.rangesStore.ranges[0].allocRange.Has(net.ParseIP("10.0.10.125")) {
		t.Fatal("Expected IP '10.0.10.125' to be released")
	}
}

// TestNonMatchingLBClass tests that services, which explicitly set a LBClass which doesn't match any of the classes
// LBIPAM looks for, are ignored by LBIPAM.
func TestNonMatchingLBClass(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	lbClass := "net.example/some-other-class"
	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: slim_core_v1.ServiceSpec{
				Type:              slim_core_v1.ServiceTypeLoadBalancer,
				LoadBalancerClass: &lbClass,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		t.Error("Unexpected patch to a service")

		return true
	}, 100*time.Millisecond)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if !await.Block() {
		t.Fatal("Unexpected service status update")
	}
}

// TestChangePoolSelector tests that when the selector of a pool changes, all services which no longer match are
// stripped of their allocations and assignments
func TestChangePoolSelector(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	poolA.Spec.ServiceSelector = &slim_meta_v1.LabelSelector{
		MatchLabels: map[string]string{"color": "red"},
	}
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true, nil)

	fixture.coreCS.Tracker().Add(
		&slim_core_v1.Service{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
				Labels: map[string]string{
					"color": "red",
				},
			},
			Spec: slim_core_v1.ServiceSpec{
				Type: slim_core_v1.ServiceTypeLoadBalancer,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Error("Expected service to receive exactly one ingress IP")
			return true
		}

		return true
	}, time.Second)

	go fixture.hive.Start(context.Background())
	defer fixture.hive.Stop(context.Background())

	if await.Block() {
		t.Fatal("Expected service status update")
	}
	// If t.Error was called within the await
	if t.Failed() {
		return
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "patch" {
			return false
		}

		svc := fixture.PatchedSvc(action)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Error("Expected service to receive exactly zero ingress IPs")
			return true
		}

		return true
	}, time.Second)

	poolA.Spec.ServiceSelector.MatchLabels = map[string]string{"color": "green"}

	_, err := fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}
