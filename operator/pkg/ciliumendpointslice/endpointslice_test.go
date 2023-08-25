// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

func TestRemoveStaleCEPEntries(t *testing.T) {
	namespace := "ns"
	testCases := []struct {
		desc      string
		storeCESs []*capi_v2a1.CiliumEndpointSlice
		storeCEPs []*v2.CiliumEndpoint
		want      map[string]string
	}{
		{
			desc: "No stale CEPs",
			storeCESs: []*capi_v2a1.CiliumEndpointSlice{
				createStoreEndpointSlice("slice1", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1)}),
			},
			storeCEPs: []*v2.CiliumEndpoint{createStoreEndpoint("cep1", namespace, 1)},
			want:      map[string]string{"ns/cep1": "slice1"},
		},
		{
			desc: "Remove stale CEP",
			storeCESs: []*capi_v2a1.CiliumEndpointSlice{
				createStoreEndpointSlice("slice1", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1),
					createManagerEndpoint("cep2", 2),
				}),
			},
			storeCEPs: []*v2.CiliumEndpoint{createStoreEndpoint("cep1", namespace, 1)},
			want:      map[string]string{"ns/cep1": "slice1"},
		},
		{
			desc: "Remove duplicated CEP from single slice",
			storeCESs: []*capi_v2a1.CiliumEndpointSlice{
				createStoreEndpointSlice("slice1", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1),
					createManagerEndpoint("cep1", 1),
				}),
			},
			storeCEPs: []*v2.CiliumEndpoint{createStoreEndpoint("cep1", namespace, 1)},
			want:      map[string]string{"ns/cep1": "slice1"},
		},
		{
			desc: "Remove duplicated CEP from separate slice",
			storeCESs: []*capi_v2a1.CiliumEndpointSlice{
				createStoreEndpointSlice("slice1", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1),
				}),
				createStoreEndpointSlice("slice2", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1),
				}),
			},
			storeCEPs: []*v2.CiliumEndpoint{createStoreEndpoint("cep1", namespace, 1)},
			want:      map[string]string{"ns/cep1": ""}, // empty ces name as any ces is ok
		},
		{
			desc: "Remove old CEP from first slice",
			storeCESs: []*capi_v2a1.CiliumEndpointSlice{
				createStoreEndpointSlice("slice1", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 2),
				}),
				createStoreEndpointSlice("slice2", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1),
				}),
			},
			storeCEPs: []*v2.CiliumEndpoint{createStoreEndpoint("cep1", namespace, 1)},
			want:      map[string]string{"ns/cep1": "slice2"},
		},
		{
			desc: "Remove old CEP from second slice",
			storeCESs: []*capi_v2a1.CiliumEndpointSlice{
				createStoreEndpointSlice("slice1", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1),
				}),
				createStoreEndpointSlice("slice2", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 2),
				}),
			},
			storeCEPs: []*v2.CiliumEndpoint{createStoreEndpoint("cep1", namespace, 1)},
			want:      map[string]string{"ns/cep1": "slice1"},
		},
		{
			desc: "Big remove case with multiple stale and duplicated CEPs from multiple slices",
			storeCESs: []*capi_v2a1.CiliumEndpointSlice{
				createStoreEndpointSlice("slice1", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 1),
					createManagerEndpoint("cep2", 1),
					createManagerEndpoint("cep3", 1),
				}),
				createStoreEndpointSlice("slice2", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 2),
					createManagerEndpoint("cep4", 2),
					createManagerEndpoint("cep5", 2),
					createManagerEndpoint("cep6", 2),
				}),
				createStoreEndpointSlice("slice3", namespace, []capi_v2a1.CoreCiliumEndpoint{
					createManagerEndpoint("cep1", 2),
					createManagerEndpoint("cep4", 2),
					createManagerEndpoint("cep7", 2),
					createManagerEndpoint("cep8", 2),
					createManagerEndpoint("cep9", 2),
				}),
			},
			storeCEPs: []*v2.CiliumEndpoint{
				createStoreEndpoint("cep1", namespace, 1),
				createStoreEndpoint("cep2", namespace, 1),
				createStoreEndpoint("cep3", namespace, 1),
				createStoreEndpoint("cep4", namespace, 2),
				createStoreEndpoint("cep5", namespace, 2),
			},
			want: map[string]string{
				"ns/cep1": "slice1",
				"ns/cep2": "slice1",
				"ns/cep3": "slice1",
				"ns/cep4": "",
				"ns/cep5": "slice2",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, client := client.NewFakeClientset()
			ciliumEndpointStore := cache.NewIndexer(
				cache.DeletionHandlingMetaNamespaceKeyFunc,
				cache.Indexers{
					cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
					"identity": func(obj interface{}) ([]string, error) {
						endpointObj, ok := obj.(*v2.CiliumEndpoint)
						if !ok {
							return nil, errors.New("failed to convert cilium endpoint")
						}
						identityID := "0"
						if endpointObj.Status.Identity != nil {
							identityID = strconv.FormatInt(endpointObj.Status.Identity.ID, 10)
						}
						return []string{identityID}, nil
					},
				},
			)
			cesController := NewCESController(context.Background(), &sync.WaitGroup{}, client, 5, cesIdentityBasedSlicing, 10, 20)
			cesController.ciliumEndpointStore = ciliumEndpointStore
			manager := cesController.Manager.(*cesManagerIdentity)
			for _, cep := range tc.storeCEPs {
				ciliumEndpointStore.Add(cep)
			}
			for _, ces := range tc.storeCESs {
				cesController.ciliumEndpointSliceStore.Add(ces)
			}
			syncCESsInLocalCache(cesController.ciliumEndpointSliceStore, manager)
			cesController.removeStaleAndDuplicatedCEPEntries()
			wantedCEPs := make([]string, len(tc.want))
			i := 0
			for cep := range tc.want {
				wantedCEPs[i] = cep
				i++
			}
			assert.ElementsMatch(t, wantedCEPs, manager.getAllCEPNames())
			for cep := range tc.want {
				actualCES, exists := manager.desiredCESs.getCESName(cep)
				assert.True(t, exists)
				if tc.want[cep] != "" {
					assert.Equal(t, tc.want[cep], actualCES)
				}
			}
		})
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

func assertEqualIDs(t *testing.T, wantIdentities, gotIdentities map[string]bool) {
	t.Helper()
	if diff := cmp.Diff(wantIdentities, gotIdentities); diff != "" {
		t.Errorf("Unexpected Identites in the CES store (-want +got): \n%s", diff)
	}
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

func TestHandleErr(t *testing.T) {
	t.Run("Cache is updated on conflict", func(t *testing.T) {
		_, client := client.NewFakeClientset()
		cesController := NewCESController(context.Background(), &sync.WaitGroup{}, client, 5, cesIdentityBasedSlicing, 10, 20)
		manager := cesController.Manager

		key := "some-ces"
		initialCES := createCESWithIDs(key, []int64{1, 2})
		initialCES.Generation = 1
		manager.createCES(key)
		manager.updateCESInCache(initialCES, true)
		updatedCES := createCESWithIDs(key, []int64{1, 2})
		updatedCES.Generation = 2
		cesController.ciliumEndpointSliceStore.Add(updatedCES)

		var err error = k8s_errors.NewConflict(
			schema.GroupResource{Group: "", Resource: "ciliumendpointslices"},
			key,
			fmt.Errorf("conflict"))
		cesController.handleErr(err, key)

		managerCES, _ := manager.getCESFromCache(key)
		assert.Equal(t, updatedCES.Generation, managerCES.Generation)
	})
}
