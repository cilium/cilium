// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

func createManagerEndpoint(name string, identity int64) cilium_v2a1.CoreCiliumEndpoint {
	return cilium_v2a1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: identity,
	}
}

func createStoreEndpoint(name string, namespace string, identity int64) *cilium_v2.CiliumEndpoint {
	return &cilium_v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Status: cilium_v2.EndpointStatus{
			Identity: &cilium_v2.EndpointIdentity{
				ID: identity,
			},
			Networking: &cilium_v2.EndpointNetworking{},
		},
	}
}

func createStoreEndpointSlice(name string, namespace string, endpoints []cilium_v2a1.CoreCiliumEndpoint) *cilium_v2a1.CiliumEndpointSlice {
	return &cilium_v2a1.CiliumEndpointSlice{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
		},
		Namespace: namespace,
		Endpoints: endpoints,
	}
}

func TestSyncCESsInLocalCache(t *testing.T) {
	var r *reconciler
	var fakeClient k8sClient.FakeClientset
	m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = *c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)
	hive.Start(context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())
	cesController := &Controller{
		logger:              log,
		clientset:           fakeClient.Clientset,
		ciliumEndpoint:      ciliumEndpoint,
		ciliumEndpointSlice: ciliumEndpointSlice,
		reconciler:          r,
		manager:             m,
		writeQPSBurst:       2,
		writeQPSLimit:       1,
		enqueuedAt:          make(map[CESName]time.Time),
	}
	cesController.initializeQueue()

	cep1 := createManagerEndpoint("cep1", 1)
	cep2 := createManagerEndpoint("cep2", 1)
	cep3 := createManagerEndpoint("cep3", 2)
	cep4 := createManagerEndpoint("cep4", 2)
	ces1 := createStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})
	cesStore.CacheStore().Add(ces1)
	cep5 := createManagerEndpoint("cep5", 1)
	cep6 := createManagerEndpoint("cep6", 1)
	cep7 := createManagerEndpoint("cep7", 2)
	ces2 := createStoreEndpointSlice("ces2", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep5, cep6, cep7})
	cesStore.CacheStore().Add(ces2)

	cesController.syncCESsInLocalCache(context.Background())

	mapping := m.mapping

	cesN, _ := mapping.getCESName(NewCEPName("cep1", "ns"))
	assert.Equal(t, cesN, NewCESName("ces1"))
	cesN, _ = mapping.getCESName(NewCEPName("cep2", "ns"))
	assert.Equal(t, cesN, NewCESName("ces1"))
	cesN, _ = mapping.getCESName(NewCEPName("cep3", "ns"))
	assert.Equal(t, cesN, NewCESName("ces1"))
	cesN, _ = mapping.getCESName(NewCEPName("cep4", "ns"))
	assert.Equal(t, cesN, NewCESName("ces1"))
	cesN, _ = mapping.getCESName(NewCEPName("cep5", "ns"))
	assert.Equal(t, cesN, NewCESName("ces2"))
	cesN, _ = mapping.getCESName(NewCEPName("cep6", "ns"))
	assert.Equal(t, cesN, NewCESName("ces2"))
	cesN, _ = mapping.getCESName(NewCEPName("cep7", "ns"))
	assert.Equal(t, cesN, NewCESName("ces2"))

	cesController.queue.ShutDown()
	hive.Stop(context.Background())
}
