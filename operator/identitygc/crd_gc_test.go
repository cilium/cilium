// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

func TestUsedIdentitiesInCESs(t *testing.T) {
	wait := make(chan struct{})
	var fakeClient k8sClient.FakeClientset
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Invoke(func(c *k8sClient.FakeClientset, cep resource.Resource[*cilium_v2.CiliumEndpoint], ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) error {
			fakeClient = *c
			ciliumEndpointSlice = ces
			close(wait)
			return nil
		}),
	)
	hive.Start(context.Background())
	<-wait

	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	// Empty store.
	gotIdentities := usedIdentitiesInCESs(cesStore)
	wantIdentities := make(map[string]bool)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 5 IDs in the store.
	cesA := createCESWithIDs("cesA", []int64{1, 2, 3, 4, 5})
	fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(context.Background(), cesA, meta_v1.CreateOptions{})
	time.Sleep(50 * time.Millisecond)
	wantIdentities["1"] = true
	wantIdentities["2"] = true
	wantIdentities["3"] = true
	wantIdentities["4"] = true
	wantIdentities["5"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 10 IDs in the store.
	cesB := createCESWithIDs("cesB", []int64{10, 20, 30, 40, 50})
	fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(context.Background(), cesB, meta_v1.CreateOptions{})
	time.Sleep(50 * time.Millisecond)
	wantIdentities["10"] = true
	wantIdentities["20"] = true
	wantIdentities["30"] = true
	wantIdentities["40"] = true
	wantIdentities["50"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	hive.Stop(context.Background())
}

func createCESWithIDs(cesName string, ids []int64) *cilium_v2a1.CiliumEndpointSlice {
	ces := &cilium_v2a1.CiliumEndpointSlice{ObjectMeta: meta_v1.ObjectMeta{Name: cesName}}
	for _, id := range ids {
		cep := cilium_v2a1.CoreCiliumEndpoint{IdentityID: id}
		ces.Endpoints = append(ces.Endpoints, cep)
	}
	return ces
}

func assertEqualIDs(t *testing.T, wantIdentities, gotIdentities map[string]bool) {
	t.Helper()
	if diff := cmp.Diff(wantIdentities, gotIdentities); diff != "" {
		t.Errorf("Unexpected Identites in the CES store (-want +got): \n%s", diff)
	}
}
