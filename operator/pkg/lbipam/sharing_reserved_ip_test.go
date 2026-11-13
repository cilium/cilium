// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"testing"

	"github.com/cilium/cilium/pkg/annotation"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// TestRequestReservedFirstLastIPWithSharingKey is the regression test for
// https://github.com/cilium/cilium/issues/48779: a service that requests a
// pool's reserved first/last IP (AllowFirstLastIPs: No) while also
// supplying a sharing key must be denied, not panic. The reserved IP is
// allocated with a nil *sharingCluster placeholder, and satisfySpecificIPRequests
// called cluster.IsCompatible(sv) on that nil receiver whenever a sharing
// key was present, dereferencing cluster.Services and crashing the operator.
func TestRequestReservedFirstLastIPWithSharingKey(t *testing.T) {
	pool := mkPool(poolAUID, "pool-a", []string{"10.0.10.16/30"})
	pool.Spec.AllowFirstLastIPs = cilium_api_v2.AllowFirstLastIPNo
	fixture := mkTestFixture(t, true, true)
	fixture.UpsertPool(t, pool)

	policy := slim_core_v1.IPFamilyPolicySingleStack
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
			Type:           slim_core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
			IPFamilies: []slim_core_v1.IPFamily{
				slim_core_v1.IPv4Protocol,
			},
			// 10.0.10.16 is the reserved network address of the /30 pool
			// above; AllowFirstLastIPs: No keeps it out of the allocatable
			// range regardless of a sharing key.
			LoadBalancerIP: "10.0.10.16",
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UpsertSvc panicked requesting a reserved IP with a sharing key: %v", r)
		}
	}()
	fixture.UpsertSvc(t, svcA)

	svcA = fixture.GetSvc("default", "service-a")
	if len(svcA.Status.LoadBalancer.Ingress) != 0 {
		t.Error("Expected the reserved IP request to be denied, not satisfied")
	}
}
