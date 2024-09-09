// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// TestConflictResolution tests that, upon initialization, LB IPAM will detect conflicts between pools,
// internally disables one of the pools, and notifies the user via a status update.
// Next, we update the conflicting pool to remove the offending range, this should re-enable the pool.
func TestConflictResolution(t *testing.T) {
	fixture := mkTestFixture(true, false)

	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture.UpsertPool(t, poolA)

	poolB := mkPool(poolBUID, "pool-b", []string{"10.0.10.0/24", "FF::0/48"})
	poolB.CreationTimestamp = meta_v1.Date(2022, 10, 16, 13, 30, 00, 0, time.UTC)
	fixture.UpsertPool(t, poolB)

	poolB = fixture.GetPool("pool-b")
	if !isPoolConflicting(poolB) {
		t.Fatal("Pool B should be conflicting")
	}

	// All ranges of a conflicting pool must be disabled
	poolBRanges, _ := fixture.lbipam.rangesStore.GetRangesForPool("pool-b")
	for _, r := range poolBRanges {
		if !r.internallyDisabled {
			t.Fatalf("Range '%s' from pool B hasn't been disabled", ipNetStr(r))
		}
	}

	// Phase 2, resolving the conflict

	// Remove the conflicting range
	poolB.Spec.Blocks = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock{
		{
			Cidr: cilium_api_v2alpha1.IPv4orIPv6CIDR("FF::0/48"),
		},
	}
	fixture.UpsertPool(t, poolB)

	poolB = fixture.GetPool("pool-b")
	if isPoolConflicting(poolB) {
		t.Fatal("Pool B should no longer be conflicting")
	}
}

// TestPoolInternalConflict tests that LB-IPAM can detect when two ranges in the same pool have overlapping CIDRs,
// mark the pool as `conflicting` and disables all ranges. Then de-conflict the pool by removing one of the ranges
// after which the pool should be no longer be marked conflicting.
func TestPoolInternalConflict(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24", "10.0.10.64/28"})
	fixture := mkTestFixture(true, false)
	fixture.UpsertPool(t, poolA)
	poolA = fixture.GetPool("pool-a")

	if !isPoolConflicting(poolA) {
		t.Fatal("Pool A should be conflicting")
	}

	poolA.Spec.Blocks = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock{
		{
			Cidr: "10.0.10.0/24",
		},
	}
	fixture.UpsertPool(t, poolA)
	poolA = fixture.GetPool("pool-a")

	if isPoolConflicting(poolA) {
		t.Fatal("Expected pool to be un-marked conflicting")
	}
}

// TestAllocHappyPath tests that an existing service will first get an IPv4 address assigned, then when they request
// an IPv6 instead, the IPv4 is freed and an IPv6 is allocated for them.
func TestAllocHappyPath(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24", "FF::0/48"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	// Initially request only an IPv4
	policy := slim_core_v1.IPFamilyPolicySingleStack
	svcA := &slim_core_v1.Service{
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
	}
	fixture.UpsertSvc(t, svcA)

	svcA = fixture.GetSvc("default", "service-a")
	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if len(svcA.Status.Conditions) != 1 {
		t.Error("Expected service to receive exactly one condition")
	}

	if svcA.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Unexpected condition type assigned to service")
	}

	if svcA.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
		t.Error("Unexpected condition status assigned to service")
	}

	// Switch to requesting an IPv6 address
	svcA.Spec.IPFamilies = []slim_core_v1.IPFamily{
		slim_core_v1.IPv6Protocol,
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	// The second update allocates the new IPv6
	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() != nil {
		t.Error("Expected service to receive a IPv6 address")
	}

	// Switch back to requesting an IPv4 address
	svcA.Spec.IPFamilies = []slim_core_v1.IPFamily{
		slim_core_v1.IPv4Protocol,
	}
	fixture.UpsertSvc(t, svcA)

	svcA = fixture.GetSvc("default", "service-a")

	// The second update allocates the new IPv4
	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}
}

// This test makes sure that two services with the same sharing key get assigned the same IP.
// And when the sharing key changes the IP is changed as well.
func TestSharedServiceUpdatedSharingKey(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, false)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMSharingKeyAlias: "key-1",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{{
				Port: 80,
			}},
		},
	}
	fixture.UpsertSvc(t, svcA)

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMSharingKeyAlias: "key-1",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{{
				Port: 81,
			}},
		},
	}
	fixture.UpsertSvc(t, svcB)

	svcA = fixture.GetSvc("default", "service-a")
	svcB = fixture.GetSvc("default", "service-b")

	if svcA.Status.LoadBalancer.Ingress[0].IP != svcB.Status.LoadBalancer.Ingress[0].IP {
		t.Fatal("IPs should be the same")
	}

	svcB.Annotations[annotation.LBIPAMSharingKeyAlias] = "key-2"
	fixture.UpsertSvc(t, svcB)
	svcB = fixture.GetSvc("default", "service-b")

	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP == svcA.Status.LoadBalancer.Ingress[0].IP {
		t.Error("Expected service to receive a different ingress IP")
	}
}

// This test makes sure that two services with the same sharing key get assigned the same IP.
// And when the ports change to overlap the IP is changed as well.
func TestSharedServiceUpdatedPorts(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, false)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMSharingKeyAlias: "key-1",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{{
				Port: 80,
			}},
		},
	}
	fixture.UpsertSvc(t, svcA)

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMSharingKeyAlias: "key-1",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{{
				Port: 81,
			}},
		},
	}
	fixture.UpsertSvc(t, svcB)

	svcA = fixture.GetSvc("default", "service-a")
	svcB = fixture.GetSvc("default", "service-b")

	if svcA.Status.LoadBalancer.Ingress[0].IP != svcB.Status.LoadBalancer.Ingress[0].IP {
		t.Fatal("IPs should be the same")
	}

	svcB.Spec.Ports[0].Port = 80
	fixture.UpsertSvc(t, svcB)
	svcB = fixture.GetSvc("default", "service-b")

	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP == svcA.Status.LoadBalancer.Ingress[0].IP {
		t.Error("Expected service to receive a different ingress IP")
	}
}

// TestSharingKey tests that the sharing key causes the LB IPAM to reuse the same IP for services with the same
// sharing key. This test also verifies that the ip is not reused if there is a conflict with another service.
func TestSharingKey(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-a",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
		},
	}
	fixture.UpsertSvc(t, svcA)

	svcA = fixture.GetSvc("default", "service-a")
	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	svcIP := svcA.Status.LoadBalancer.Ingress[0].IP

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-a",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
		},
	}
	fixture.UpsertSvc(t, svcB)

	svcB = fixture.GetSvc("default", "service-b")
	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcB.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP != svcIP {
		t.Error("Expected service to receive the same IP as service-a")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}

	svcC := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-c",
			Namespace: "default",
			UID:       serviceCUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-b",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{
				{
					Port: 80,
				},
			},
		},
	}
	fixture.UpsertSvc(t, svcC)
	svcC = fixture.GetSvc("default", "service-c")

	if len(svcC.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcC.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcC.Status.LoadBalancer.Ingress[0].IP == svcIP {
		t.Error("Expected service to receive a different IP than service-a")
	}

	svcIP2 := svcC.Status.LoadBalancer.Ingress[0].IP

	err := fixture.svcClient.Services("default").Delete(context.Background(), "service-a", meta_v1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	fixture.DeleteSvc(t, svcA)
	fixture.DeleteSvc(t, svcB)

	// The IP is released because service-b is no longer using it
	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); has {
		t.Fatal("Service IP hasn't been released")
	}

	svcA = &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-b",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{
				{
					Port: 80,
				},
			},
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcA.Status.LoadBalancer.Ingress[0].IP == svcIP2 {
		t.Error("Expected service to receive a different IP than service-c")
	}

	svcB = &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-b",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{
				{
					Port: 81,
				},
			},
		},
	}
	fixture.UpsertSvc(t, svcB)
	svcB = fixture.GetSvc("default", "service-b")

	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcB.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP != svcIP2 {
		t.Error("Expected service to receive the same IP as service-c")
	}

	fixture.DeleteSvc(t, svcC)

	// The IP is not released because service-b is still using it
	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP2)); !has {
		t.Fatal("Service IP has been released")
	}

	fixture.DeleteSvc(t, svcB)

	// The IP is released because service-b is no longer using it
	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP2)); has {
		t.Fatal("Service IP hasn't been released")
	}
}

func TestRegressionSharedKeyReaddBug(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-a",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
		},
	}
	fixture.UpsertSvc(t, svcA)

	svcA = fixture.GetSvc("default", "service-a")
	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	svcIP := svcA.Status.LoadBalancer.Ingress[0].IP

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-a",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
		},
	}
	fixture.UpsertSvc(t, svcB)

	svcB = fixture.GetSvc("default", "service-b")
	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcB.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP != svcIP {
		t.Error("Expected service to receive the same IP as service-a")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}

	fixture.DeleteSvc(t, svcB)

	fixture.UpsertSvc(t, svcB)

	svcB = fixture.GetSvc("default", "service-b")
	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcB.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP != svcIP {
		t.Error("Expected service to receive the same IP as service-a")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}
}

// TestSharingCrossNamespace tests that the sharing of IPs is possible cross namespace when allowed.
func TestSharingCrossNamespace(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "ns-a",
			UID:       serviceAUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key":             "key-a",
				"io.cilium/lb-ipam-sharing-cross-namespace": "ns-b",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
		},
	}
	fixture.UpsertSvc(t, svcA)

	svcA = fixture.GetSvc("ns-a", "service-a")
	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	svcIP := svcA.Status.LoadBalancer.Ingress[0].IP

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "ns-b",
			UID:       serviceBUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key":             "key-a",
				"io.cilium/lb-ipam-sharing-cross-namespace": "*",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
		},
	}
	fixture.UpsertSvc(t, svcB)

	svcB = fixture.GetSvc("ns-b", "service-b")
	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcB.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP != svcIP {
		t.Error("Expected service to receive the same IP as service-a")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}

	svcC := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-c",
			Namespace: "ns-c",
			UID:       serviceCUID,
			Annotations: map[string]string{
				"io.cilium/lb-ipam-sharing-key": "key-a",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{
				{
					Port: 80,
				},
			},
		},
	}
	fixture.UpsertSvc(t, svcC)
	svcC = fixture.GetSvc("ns-c", "service-c")

	if len(svcC.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcC.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcC.Status.LoadBalancer.Ingress[0].IP == svcIP {
		t.Error("Expected service to receive a different IP than service-a")
	}

	fixture.DeleteSvc(t, svcA)
	fixture.DeleteSvc(t, svcB)
	fixture.DeleteSvc(t, svcC)
}

// TestServiceDelete tests the service deletion logic. It makes sure that the IP that was assigned to the service is
// released after the service is deleted so it can be re-assigned.
func TestServiceDelete(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
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
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	svcIP := svcA.Status.LoadBalancer.Ingress[0].IP

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); !has {
		t.Fatal("Service IP hasn't been allocated")
	}

	fixture.DeleteSvc(t, svcA)

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(svcIP)); has {
		t.Fatal("Service IP hasn't been released")
	}
}

// TestReallocOnInit tests the edge case where an existing service has an IP assigned for which there is no IP Pool.
// LB IPAM should take the unknown IP away and allocate a new and valid IP. This scenario can happen when a service
// passes ownership from on controller to another or when a pool is deleted while the operator is down.
func TestReallocOnInit(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	// Initially request only an IPv4
	policy := slim_core_v1.IPFamilyPolicySingleStack
	svcA := &slim_core_v1.Service{
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
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(svcA.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if svcA.Status.LoadBalancer.Ingress[0].IP == "192.168.1.12" {
		t.Error("Expected ingress IP to not be the initial, bad IP")
	}

	if len(svcA.Status.Conditions) != 1 {
		t.Error("Expected service to receive exactly one condition")
	}

	if svcA.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected second condition to be svc-satisfied:true")
	}

	if svcA.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
		t.Error("Expected second condition to be svc-satisfied:true")
	}
}

// TestAllocOnInit tests that on init, ingress IPs on services which match configured pools are imported
// and marked as allocated. This is crucial when restarting the operator in a running cluster.
func TestAllocOnInit(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	policy := slim_core_v1.IPFamilyPolicySingleStack
	svcA := &slim_core_v1.Service{
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
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	svcB := &slim_core_v1.Service{
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
	}
	fixture.UpsertSvc(t, svcB)

	if svcA.Status.LoadBalancer.Ingress[0].IP != "10.0.10.123" {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP != "10.0.10.124" {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr("10.0.10.123")); !has {
		t.Fatal("Expected the imported IP to be allocated")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr("10.0.10.124")); !has {
		t.Fatal("Expected the imported IP to be allocated")
	}
}

// TestAllocSharedOnInit tests that on init, ingress IPs on services which match configured pools are imported
// and marked as allocated, and that services sharing IPs are allocated the same IP.
func TestAllocSharedOnInit(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	policy := slim_core_v1.IPFamilyPolicySingleStack
	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMSharingKey: "key-1",
			},
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
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
			Annotations: map[string]string{
				annotation.LBIPAMSharingKey: "key-1",
			},
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
	}
	fixture.UpsertSvc(t, svcB)
	svcB = fixture.GetSvc("default", "service-b")

	if svcA.Status.LoadBalancer.Ingress[0].IP != "10.0.10.123" {
		t.Error("Expected service A to receive ingress IP 10.0.10.123 got ", svcA.Status.LoadBalancer.Ingress[0].IP)
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP != "10.0.10.123" {
		t.Error("Expected service B to receive ingress IP 10.0.10.123, got ", svcB.Status.LoadBalancer.Ingress[0].IP)
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

	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	policy := slim_core_v1.IPFamilyPolicySingleStack
	matchingService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "red-service",
			Namespace: "default",
			UID:       serviceAUID,
			Labels: map[string]string{
				"color": "red",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}
	fixture.UpsertSvc(t, matchingService)
	matchingService = fixture.GetSvc("default", "red-service")

	if len(matchingService.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(matchingService.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if len(matchingService.Status.Conditions) != 1 {
		t.Error("Expected service to receive exactly one condition")
	}

	if matchingService.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be svc-satisfied:true")
	}

	if matchingService.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
		t.Error("Expected condition to be svc-satisfied:true")
	}

	nonMatchingService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "blue-service",
			Namespace: "default",
			UID:       serviceBUID,
			Labels: map[string]string{
				"color": "blue",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}
	fixture.UpsertSvc(t, nonMatchingService)
	nonMatchingService = fixture.GetSvc("default", "blue-service")

	if len(nonMatchingService.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to not receive any ingress IPs")
	}

	if len(nonMatchingService.Status.Conditions) != 1 {
		t.Error("Expected service to receive exactly one condition")
	}

	if nonMatchingService.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be svc-satisfied:false")
	}

	if nonMatchingService.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
		t.Error("Expected condition to be svc-satisfied:false")
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

	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

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
	fixture.UpsertSvc(t, matchingService)
	matchingService = fixture.GetSvc("tenant-one", "red-service")

	if len(matchingService.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(matchingService.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	if len(matchingService.Status.Conditions) != 1 {
		t.Error("Expected service to receive exactly one condition")
	}

	if matchingService.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be svc-satisfied:true")
	}

	if matchingService.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
		t.Error("Expected condition to be svc-satisfied:true")
	}

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
	fixture.UpsertSvc(t, nonMatchingService)
	nonMatchingService = fixture.GetSvc("tenant-two", "blue-service")

	if len(nonMatchingService.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to not receive any ingress IPs")
	}

	if len(nonMatchingService.Status.Conditions) != 1 {
		t.Error("Expected service to receive exactly one condition")
	}

	if nonMatchingService.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be svc-satisfied:false")
	}

	if nonMatchingService.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
		t.Error("Expected condition to be svc-satisfied:false")
	}
}

// TestChangeServiceType tests that we don't handle non-LB services, then we update the type and check that we start
// handling the service, then switch the type again and verify that we release the allocated IP.
func TestChangeServiceType(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	// This ClusterIP service should be ignored
	clusterIPService := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeClusterIP,
		},
	}
	fixture.UpsertSvc(t, clusterIPService)
	clusterIPService = fixture.GetSvc("default", "service-a")

	if len(clusterIPService.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to not receive any ingress IPs")
	}

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
	fixture.UpsertSvc(t, updatedService)
	updatedService = fixture.GetSvc("default", "service-a")

	if len(updatedService.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if net.ParseIP(updatedService.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
		t.Error("Expected service to receive a IPv4 address")
	}

	assignedIP := updatedService.Status.LoadBalancer.Ingress[0].IP

	if len(updatedService.Status.Conditions) != 1 {
		t.Error("Expected service to receive exactly one condition")
	}

	if updatedService.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be svc-satisfied:true")
	}

	if updatedService.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
		t.Error("Expected condition to be svc-satisfied:true")
	}

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
	fixture.UpsertSvc(t, updatedService)
	updatedService = fixture.GetSvc("default", "service-a")

	if len(updatedService.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to have no ingress IPs")
	}

	if len(updatedService.Status.Conditions) != 0 {
		t.Error("Expected service to have no conditions")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr(assignedIP)); has {
		t.Fatal("Expected assigned IP to be released")
	}
}

// TestAllowFirstLastIPs tests that first and last IPs are assigned when we set .spec.allowFirstLastIPs to yes.
func TestAllowFirstLastIPs(t *testing.T) {
	pool := mkPool(poolAUID, "pool-a", []string{"10.0.10.16/30"})
	pool.Spec.AllowFirstLastIPs = cilium_api_v2alpha1.AllowFirstLastIPYes
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, pool)

	policy := slim_core_v1.IPFamilyPolicySingleStack
	svcA := &slim_core_v1.Service{
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
			LoadBalancerIP: "10.0.10.16",
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to have one ingress IPs")
	}

	if len(svcA.Status.Conditions) != 1 {
		t.Error("Expected service to have one conditions")
	}

	if svcA.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be svc-satisfied:true")
	}

	if svcA.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
		t.Error("Expected condition to be svc-satisfied:true")
	}
}

// TestUpdateAllowFirstAndLastIPs tests that first and last IPs are assigned when we update the
// .spec.allowFirstLastIPs field.
func TestUpdateAllowFirstAndLastIPs(t *testing.T) {
	// Add pool which does not allow first and last IPs
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.16/30"})
	poolA.Spec.AllowFirstLastIPs = cilium_api_v2alpha1.AllowFirstLastIPNo
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	policy := slim_core_v1.IPFamilyPolicySingleStack
	svcA := &slim_core_v1.Service{
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
			LoadBalancerIP: "10.0.10.16",
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	// First confirm that by default, first and last IPs are not allowed and thus the first and last IPs of the CIDR
	// are reserved.

	if len(svcA.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to have zero ingress IPs")
	}

	if len(svcA.Status.Conditions) != 1 {
		t.Error("Expected service to have one conditions")
	}

	if svcA.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be svc-satisfied:false")
	}

	if svcA.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
		t.Error("Expected condition to be svc-satisfied:false")
	}

	// Then update the pool and confirm that the service got the first IP.

	poolA = fixture.GetPool("pool-a")
	poolA.Spec.AllowFirstLastIPs = cilium_api_v2alpha1.AllowFirstLastIPYes
	fixture.UpsertPool(t, poolA)

	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to have one ingress IPs")
	}

	if len(svcA.Status.Conditions) != 1 {
		t.Error("Expected service to have one conditions")
	}

	if svcA.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition 0 to be svc-satisfied:true")
	}

	if svcA.Status.Conditions[0].Status != slim_meta_v1.ConditionTrue {
		t.Error("Expected condition 0 to be svc-satisfied:true")
	}
}

// TestRequestIPs tests that we can request specific IPs
func TestRequestIPs(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.10.20",
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if svcA.Status.LoadBalancer.Ingress[0].IP != "10.0.10.20" {
		t.Error("Expected service to receive IP '10.0.10.20'")
	}

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
			Annotations: map[string]string{
				annotation.LBIPAMIPKeyAlias: "10.0.10.22,10.0.10.23",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.10.21",
		},
	}
	fixture.UpsertSvc(t, svcB)
	svcB = fixture.GetSvc("default", "service-b")

	if len(svcB.Status.LoadBalancer.Ingress) != 3 {
		t.Error("Expected service to receive exactly three ingress IPs")
	}

	first := false
	second := false
	third := false

	for _, ingress := range svcB.Status.LoadBalancer.Ingress {
		switch ingress.IP {
		case "10.0.10.21":
			first = true
		case "10.0.10.22":
			second = true
		case "10.0.10.23":
			third = true
		default:
			t.Error("Unexpected ingress IP")
		}
	}

	if !first {
		t.Error("Expected service to receive IP '10.0.10.21'")
	}

	if !second {
		t.Error("Expected service to receive IP '10.0.10.22'")
	}

	if !third {
		t.Error("Expected service to receive IP '10.0.10.23'")
	}

	// request an already allocated IP
	svcC := &slim_core_v1.Service{
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
	fixture.UpsertSvc(t, svcC)
	svcC = fixture.GetSvc("default", "service-c")

	if len(svcC.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive no ingress IPs")
	}

	if len(svcC.Status.Conditions) != 1 {
		t.Error("Expected service to have one conditions")
	}

	if svcC.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
		t.Error("Expected condition to be request-valid:false")
	}

	if svcC.Status.Conditions[0].Status != slim_meta_v1.ConditionFalse {
		t.Error("Expected condition to be request-valid:false")
	}

	if svcC.Status.Conditions[0].Reason != "already_allocated" {
		t.Error("Expected condition reason to be 'already_allocated'")
	}
}

func TestSharedServicesUpdateSharingKeyAndRequestedIP(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, false)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMIPsKey:     "10.0.10.22",
				annotation.LBIPAMSharingKey: "key-1",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{{
				Port: 80,
			}},
		},
	}
	fixture.UpsertSvc(t, svcA)

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMIPsKey:     "10.0.10.33",
				annotation.LBIPAMSharingKey: "key-2",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{{
				Port: 81,
			}},
		},
	}
	fixture.UpsertSvc(t, svcB)

	svcC := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-c",
			Namespace: "default",
			UID:       serviceAUID,
			Annotations: map[string]string{
				annotation.LBIPAMIPsKey:     "10.0.10.33",
				annotation.LBIPAMSharingKey: "key-2",
			},
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			Ports: []slim_core_v1.ServicePort{{
				Port: 82,
			}},
		},
	}
	fixture.UpsertSvc(t, svcC)

	svcA = fixture.GetSvc("default", "service-a")
	svcB = fixture.GetSvc("default", "service-b")
	svcC = fixture.GetSvc("default", "service-c")

	if svcB.Status.LoadBalancer.Ingress[0].IP != svcC.Status.LoadBalancer.Ingress[0].IP {
		t.Fatal("IPs of service B & C should be the same")
	}

	svcC.Annotations[annotation.LBIPAMIPsKey] = "10.0.10.22"
	svcC.Annotations[annotation.LBIPAMSharingKey] = "key-1"

	fixture.UpsertSvc(t, svcC)

	svcC = fixture.GetSvc("default", "service-c")

	if svcA.Status.LoadBalancer.Ingress[0].IP != svcC.Status.LoadBalancer.Ingress[0].IP {
		t.Fatal("IPs of service A & C should be the same")
	}

	if svcB.Status.LoadBalancer.Ingress[0].IP == svcC.Status.LoadBalancer.Ingress[0].IP {
		t.Error("Expected service B & C to receive a different ingress IP")
	}
}

// TestAddPool tests that adding a new pool will satisfy services.
func TestAddPool(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.20.10",
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive no ingress IPs")
	}

	twentyPool := mkPool(poolBUID, "pool-b", []string{"10.0.20.0/24"})
	fixture.UpsertPool(t, twentyPool)

	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if svcA.Status.LoadBalancer.Ingress[0].IP != "10.0.20.10" {
		t.Error("Expected service to receive IP '10.0.20.10'")
	}
}

// TestAddRange tests adding a range to a pool will satisfy services which have not been able to get an IP
func TestAddRange(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.20.10",
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive no ingress IPs")
	}

	poolA = fixture.GetPool("pool-a")
	poolA.Spec.Blocks = append(poolA.Spec.Blocks, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock{
		Cidr: "10.0.20.0/24",
	})
	fixture.UpsertPool(t, poolA)

	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if svcA.Status.LoadBalancer.Ingress[0].IP != "10.0.20.10" {
		t.Error("Expected service to receive IP '10.0.20.10'")
	}
}

// TestDisablePool tests that disabling a pool will not remove existing allocations but will stop new allocations.
// Then re-enable the pool and see that the pool resumes allocating IPs
func TestDisablePool(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	poolA = fixture.GetPool("pool-a")
	poolA.Spec.Disabled = true
	fixture.UpsertPool(t, poolA)

	if !fixture.lbipam.rangesStore.ranges[0].externallyDisabled {
		t.Fatal("The range has not been externally disabled")
	}

	svcB := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}
	fixture.UpsertSvc(t, svcB)
	svcB = fixture.GetSvc("default", "service-b")

	if len(svcB.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive no ingress IPs")
	}

	poolA = fixture.GetPool("pool-a")
	poolA.Spec.Disabled = false
	fixture.UpsertPool(t, poolA)

	svcB = fixture.GetSvc("default", "service-b")

	if len(svcB.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}
}

// TestPoolDelete tests that when a pool is deleted, all of the IPs from that pool are released and that any effected
// services get a new IP from another pool.
func TestPoolDelete(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	poolB := mkPool(poolBUID, "pool-b", []string{"10.0.20.0/24"})

	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)
	fixture.UpsertPool(t, poolB)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	var allocPool string
	if strings.HasPrefix(svcA.Status.LoadBalancer.Ingress[0].IP, "10.0.10") {
		allocPool = "pool-a"
	} else {
		allocPool = "pool-b"
	}

	if allocPool == "pool-a" {
		poolA = fixture.GetPool("pool-a")
		fixture.DeletePool(t, poolA)
	} else {
		poolB = fixture.GetPool("pool-b")
		fixture.DeletePool(t, poolB)
	}

	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if strings.HasPrefix(svcA.Status.LoadBalancer.Ingress[0].IP, "10.0.10") {
		if allocPool == "pool-a" {
			t.Error("New IP was allocated from deleted pool")
		}
	} else {
		if allocPool == "pool-b" {
			t.Error("New IP was allocated from deleted pool")
		}
	}
}

// TestRangeDelete tests that when a range is deleted from a pool, all of the IPs from that range are released and
// that any effected services get a new IP from another range.
func TestRangeDelete(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}
	assignedIP := svcA.Status.LoadBalancer.Ingress[0].IP

	poolA = fixture.GetPool("pool-a")
	// Add a new CIDR, this should not have any effect on the existing service.
	poolA.Spec.Blocks = append(poolA.Spec.Blocks, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock{
		Cidr: "10.0.20.0/24",
	})
	fixture.UpsertPool(t, poolA)

	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if svcA.Status.LoadBalancer.Ingress[0].IP != assignedIP {
		t.Error("Expected service to keep the same IP")
	}

	poolA = fixture.GetPool("pool-a")
	// Remove the existing range, this should trigger the re-allocation of the existing service
	poolA.Spec.Blocks = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock{
		{
			Cidr: "10.0.20.0/24",
		},
	}
	fixture.UpsertPool(t, poolA)

	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	if !strings.HasPrefix(svcA.Status.LoadBalancer.Ingress[0].IP, "10.0.20") {
		t.Error("Expected new ingress to be in the 10.0.20.0/24 range")
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
				lbIPAMParams: lbIPAMParams{
					ipv4Enabled: tt.IPv4Enabled,
					ipv6Enabled: tt.IPv6Enabled,
				},
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
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

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
	fixture.UpsertSvc(t, svc1)
	svc1 = fixture.GetSvc("default", "service-a")

	if len(svc1.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	svc1 = svc1.DeepCopy()
	svc1.Labels = map[string]string{
		"color": "green",
	}
	fixture.UpsertSvc(t, svc1)

	svc1 = fixture.GetSvc("default", "service-a")

	if len(svc1.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive exactly zero ingress IPs")
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
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
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
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if svcA.Status.Conditions[0].Reason != "pool_selector_mismatch" {
		t.Error("Expected service to receive 'pool_selector_mismatch' condition")
	}
}

// TestRemoveRequestedIP tests that removing a requested IP from the spec will free the IP from the pool and remove
// it from the ingress list.
func TestRemoveRequestedIP(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

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
	fixture.UpsertSvc(t, svc1)
	svc1 = fixture.GetSvc("default", "service-a")

	if len(svc1.Status.LoadBalancer.Ingress) != 3 {
		t.Error("Expected service to receive exactly three ingress IP")
	}

	svc1 = svc1.DeepCopy()
	svc1.Annotations = map[string]string{
		"io.cilium/lb-ipam-ips": "10.0.10.124",
	}

	fixture.UpsertSvc(t, svc1)
	svc1 = fixture.GetSvc("default", "service-a")

	if len(svc1.Status.LoadBalancer.Ingress) != 2 {
		t.Error("Expected service to receive exactly two ingress IPs")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr("10.0.10.123")); !has {
		t.Fatal("Expected IP '10.0.10.123' to be allocated")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr("10.0.10.124")); !has {
		t.Fatal("Expected IP '10.0.10.124' to be allocated")
	}

	if _, has := fixture.lbipam.rangesStore.ranges[0].alloc.Get(netip.MustParseAddr("10.0.10.125")); has {
		t.Fatal("Expected IP '10.0.10.125' to be released")
	}
}

// TestNonMatchingLBClass tests that services, which explicitly set a LBClass which doesn't match any of the classes
// LBIPAM looks for, are ignored by LBIPAM.
func TestNonMatchingLBClass(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	lbClass := "net.example/some-other-class"
	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type:              slim_core_v1.ServiceTypeLoadBalancer,
			LoadBalancerClass: &lbClass,
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive no ingress IPs")
	}
}

// TestRequiredLBClass tests that when LBIPAM is configured to only allocate IPs for services with a specific
// LoadBalancerClass, we leave services without a LoadBalancerClass alone.
func TestRequiredLBClass(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture(true, true)

	// Enable the requirement for a specific LBClass and set a class to look for
	fixture.lbipam.config.LBIPAMRequireLBClass = true
	fixture.lbipam.lbClasses = []string{cilium_api_v2alpha1.BGPLoadBalancerClass}

	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive no ingress IPs")
	}

	lbClass := cilium_api_v2alpha1.BGPLoadBalancerClass
	svcA.Spec.LoadBalancerClass = &lbClass

	fixture.UpsertSvc(t, svcA)

	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) == 0 {
		t.Error("Expected service to receive ingress IPs")
	}
}

// TestChangePoolSelector tests that when the selector of a pool changes, all services which no longer match are
// stripped of their allocations and assignments
func TestChangePoolSelector(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	poolA.Spec.ServiceSelector = &slim_meta_v1.LabelSelector{
		MatchLabels: map[string]string{"color": "red"},
	}
	fixture := mkTestFixture(true, true)
	fixture.UpsertPool(t, poolA)

	svcA := &slim_core_v1.Service{
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
	}
	fixture.UpsertSvc(t, svcA)
	svcA = fixture.GetSvc("default", "service-a")

	if len(svcA.Status.LoadBalancer.Ingress) != 1 {
		t.Error("Expected service to receive exactly one ingress IP")
	}

	poolA = fixture.GetPool("pool-a")
	poolA.Spec.ServiceSelector.MatchLabels = map[string]string{"color": "green"}
	fixture.UpsertPool(t, poolA)

	svcA = fixture.GetSvc("default", "service-a")
	if len(svcA.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected service to receive exactly zero ingress IPs")
	}
}

func TestRangeFromPrefix(t *testing.T) {
	type test struct {
		name   string
		prefix string
		from   string
		to     string
	}

	tests := []test{
		{
			name:   "/24",
			prefix: "10.0.0.0/24",
			from:   "10.0.0.0",
			to:     "10.0.0.255",
		},
		{
			name:   "/25",
			prefix: "10.0.0.0/25",
			from:   "10.0.0.0",
			to:     "10.0.0.127",
		},
		{
			name:   "offset prefix",
			prefix: "10.0.0.12/24",
			from:   "10.0.0.0",
			to:     "10.0.0.255",
		},
		{
			name:   "ipv6",
			prefix: "::0000/112",
			from:   "::0000",
			to:     "::FFFF",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			prefix, err := netip.ParsePrefix(test.prefix)
			if err != nil {
				t.Fatal(err)
			}

			expectedTo, err := netip.ParseAddr(test.to)
			if err != nil {
				tt.Fatal(err)
			}

			expectedFrom, err := netip.ParseAddr(test.from)
			if err != nil {
				tt.Fatal(err)
			}

			from, to := rangeFromPrefix(prefix)
			if to.Compare(expectedTo) != 0 {
				tt.Fatalf("expected '%s', got '%s'", expectedTo, to)
			}
			if from.Compare(expectedFrom) != 0 {
				tt.Fatalf("expected '%s', got '%s'", expectedFrom, from)
			}
		})
	}
}
