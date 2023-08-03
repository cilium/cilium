// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
)

func createManagerEndpoint(name string, identity int64) capi_v2a1.CoreCiliumEndpoint {
	return capi_v2a1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: identity,
	}
}

func createStoreEndpoint(name string, namespace string, identity int64) *v2.CiliumEndpoint {
	return &v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: v2.EndpointStatus{
			Identity: &v2.EndpointIdentity{
				ID: identity,
			},
			Networking: &v2.EndpointNetworking{},
		},
	}
}

func createStoreEndpointSlice(name string, namespace string, endpoints []capi_v2a1.CoreCiliumEndpoint) *capi_v2a1.CiliumEndpointSlice {
	return &capi_v2a1.CiliumEndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
		},
		Namespace: namespace,
		Endpoints: endpoints,
	}
}

func createCESWithIDs(cesName string, ids []int64) *capi_v2a1.CiliumEndpointSlice {
	ces := &capi_v2a1.CiliumEndpointSlice{ObjectMeta: meta_v1.ObjectMeta{Name: cesName}}
	for _, id := range ids {
		cep := capi_v2a1.CoreCiliumEndpoint{IdentityID: id}
		ces.Endpoints = append(ces.Endpoints, cep)
	}
	return ces
}

func TestSyncCESsInLocalCache(t *testing.T) {
	_, c := client.NewFakeClientset()
	cesController := NewCESController(context.Background(), &sync.WaitGroup{}, c, 5, "", 10, 20)

	cep1 := createManagerEndpoint("cep1", 1)
	cep2 := createManagerEndpoint("cep2", 1)
	cep3 := createManagerEndpoint("cep3", 2)
	cep4 := createManagerEndpoint("cep4", 2)
	ces1 := createStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})
	ceSliceStore.Add(ces1)
	cep5 := createManagerEndpoint("cep5", 1)
	cep6 := createManagerEndpoint("cep6", 1)
	cep7 := createManagerEndpoint("cep7", 2)
	ces2 := createStoreEndpointSlice("ces2", "ns", []capi_v2a1.CoreCiliumEndpoint{cep5, cep6, cep7})
	ceSliceStore.Add(ces2)

	cesController.syncCESsInLocalCache()

	mapping := cesController.Manager.(*cesManagerFcfs).mapping

	cesN, _ := mapping.getCESName("ns/cep1")
	assert.Equal(t, cesN, CESName("ces1"))
	cesN, _ = mapping.getCESName("ns/cep2")
	assert.Equal(t, cesN, CESName("ces1"))
	cesN, _ = mapping.getCESName("ns/cep3")
	assert.Equal(t, cesN, CESName("ces1"))
	cesN, _ = mapping.getCESName("ns/cep4")
	assert.Equal(t, cesN, CESName("ces1"))
	cesN, _ = mapping.getCESName("ns/cep5")
	assert.Equal(t, cesN, CESName("ces2"))
	cesN, _ = mapping.getCESName("ns/cep6")
	assert.Equal(t, cesN, CESName("ces2"))
	cesN, _ = mapping.getCESName("ns/cep7")
	assert.Equal(t, cesN, CESName("ces2"))
}

func TestEnqueueingPreIntitialization(t *testing.T) {
	_, c := client.NewFakeClientset()

	cesController := NewCESController(context.Background(), &sync.WaitGroup{}, c, 5, "", 10, 20)
	assert.Equal(t, 0, cesController.queue.Len())

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	cep2 := createStoreEndpoint("cep2", "ns", 1)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	cesController.OnEndpointUpdate(cep1)
	cesController.OnEndpointUpdate(cep2)
	cesController.OnEndpointUpdate(cep3)
	cesController.OnEndpointDelete(cep2)
	ces1 := createStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{createManagerEndpoint("cep1", 1), createManagerEndpoint("cep3", 2)})
	ceSliceStore.Add(ces1)
	ces2 := createStoreEndpointSlice("ces2", "ns", []capi_v2a1.CoreCiliumEndpoint{createManagerEndpoint("cep2", 1)})
	ceSliceStore.Add(ces2)
	time.Sleep(DefaultCESSyncTime * 2) // elements are added to the queue with a default delay
	assert.Equal(t, 0, cesController.queue.Len())
	assert.Equal(t, 4, len(cesController.preInitEnqueuedEndpointsEvents))
	assert.Equal(t, false, cesController.endpointsMappingInitialized)

	cesController.syncCESsInLocalCache()
	assert.Equal(t, true, cesController.endpointsMappingInitialized)

	cesController.processEnqueuedPreInitEndpoints()
	time.Sleep(DefaultCESSyncTime * 2) // elements are added to the queue with a default delay
	assert.Equal(t, 2, cesController.queue.Len())
}

func TestUsedIdentitiesInCESs(t *testing.T) {
	cesStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	// Empty store.
	gotIdentities := usedIdentitiesInCESs(cesStore)
	wantIdentities := make(map[string]bool)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 5 IDs in the store.
	cesA := createCESWithIDs("cesA", []int64{1, 2, 3, 4, 5})
	cesStore.Add(cesA)
	wantIdentities["1"] = true
	wantIdentities["2"] = true
	wantIdentities["3"] = true
	wantIdentities["4"] = true
	wantIdentities["5"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 10 IDs in the store.
	cesB := createCESWithIDs("cesB", []int64{10, 20, 30, 40, 50})
	cesStore.Add(cesB)
	wantIdentities["10"] = true
	wantIdentities["20"] = true
	wantIdentities["30"] = true
	wantIdentities["40"] = true
	wantIdentities["50"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)
}

func assertEqualIDs(t *testing.T, wantIdentities, gotIdentities map[string]bool) {
	t.Helper()
	if diff := cmp.Diff(wantIdentities, gotIdentities); diff != "" {
		t.Errorf("Unexpected Identites in the CES store (-want +got): \n%s", diff)
	}
}
