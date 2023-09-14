// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ces-controller")

func TestReconcileCreate(t *testing.T) {
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
	cepStore, _ := ciliumEndpoint.Store(context.Background())

	var createdSlice *v2alpha1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*v2alpha1.CiliumEndpointSlice)
		return true, nil, nil
	})

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	m.mapping.insertCES(NewCESName("ces1"), "ns")
	m.mapping.insertCES(NewCESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), NewCESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), NewCESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), NewCESName("ces2"))
	r.reconcileCES(NewCESName("ces1"))

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Equal(t, 2, len(createdSlice.Endpoints))
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(context.Background())
}

func TestReconcileUpdate(t *testing.T) {
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
	cepStore, _ := ciliumEndpoint.Store(context.Background())
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	var updatedSlice *v2alpha1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updatedSlice = pa.GetObject().(*v2alpha1.CiliumEndpointSlice)
		return true, nil, nil
	})

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	ces1 := createStoreEndpointSlice("ces1", "ns", []v2alpha1.CoreCiliumEndpoint{createManagerEndpoint("cep1", 1), createManagerEndpoint("cep3", 2)})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(NewCESName("ces1"), "ns")
	m.mapping.insertCES(NewCESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), NewCESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), NewCESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), NewCESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to cep1 and cep2
	// so it's expected that after update it would contain cep1 and cep2
	r.reconcileCES(NewCESName("ces1"))

	assert.Equal(t, "ces1", updatedSlice.Name)
	assert.Equal(t, 2, len(updatedSlice.Endpoints))
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(context.Background())
}

func TestReconcileDelete(t *testing.T) {
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
	cepStore, _ := ciliumEndpoint.Store(context.Background())
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	var deletedSlice string
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deletedSlice = pa.GetName()
		return true, nil, nil
	})

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	ces1 := createStoreEndpointSlice("ces1", "ns", []v2alpha1.CoreCiliumEndpoint{createManagerEndpoint("cep1", 1), createManagerEndpoint("cep3", 2)})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(NewCESName("ces1"), "ns")
	m.mapping.insertCES(NewCESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), NewCESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), NewCESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), NewCESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(NewCESName("ces1"))

	assert.Equal(t, "ces1", deletedSlice)

	hive.Stop(context.Background())
}

func TestReconcileNoop(t *testing.T) {
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
	cepStore, _ := ciliumEndpoint.Store(context.Background())

	noRequest := true
	fakeClient.CiliumFakeClientset.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		noRequest = false
		return true, nil, nil
	})

	cep1 := createStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := createStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := createStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	m.mapping.insertCES(NewCESName("ces1"), "ns")
	m.mapping.insertCES(NewCESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), NewCESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), NewCESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), NewCESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(NewCESName("ces1"))

	assert.Equal(t, true, noRequest)

	hive.Stop(context.Background())
}
