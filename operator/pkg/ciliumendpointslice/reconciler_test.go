// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
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
		metrics.Metric(NewMetrics),
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
	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(context.Background())

	var createdSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Equal(t, 2, len(createdSlice.Endpoints))
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(tlog, context.Background())
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
		metrics.Metric(NewMetrics),
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

	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(context.Background())
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	var updatedSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updatedSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1), tu.CreateManagerEndpoint("cep3", 2)})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to cep1 and cep2
	// so it's expected that after update it would contain cep1 and cep2
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", updatedSlice.Name)
	assert.Equal(t, 2, len(updatedSlice.Endpoints))
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(tlog, context.Background())
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
		metrics.Metric(NewMetrics),
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

	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(context.Background())
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	var deletedSlice string
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deletedSlice = pa.GetName()
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1), tu.CreateManagerEndpoint("cep3", 2)})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", deletedSlice)

	hive.Stop(tlog, context.Background())
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
		metrics.Metric(NewMetrics),
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
	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(context.Background())

	noRequest := true
	fakeClient.CiliumFakeClientset.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		noRequest = false
		return true, nil, nil
	})

	cep1 := tu.CreateStoreEndpoint("cep1", "ns", 1)
	cepStore.CacheStore().Add(cep1)
	cep2 := tu.CreateStoreEndpoint("cep2", "ns", 2)
	cepStore.CacheStore().Add(cep2)
	cep3 := tu.CreateStoreEndpoint("cep3", "ns", 2)
	cepStore.CacheStore().Add(cep3)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, true, noRequest)

	hive.Stop(tlog, context.Background())
}
