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
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ces-controller")

func TestReconcileCreate(t *testing.T) {
	var r *reconciler
	var fakeClient k8sClient.FakeClientset
	m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
	var pod resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			podResource resource.Resource[*slim_corev1.Pod],
			metrics *Metrics,
		) error {
			fakeClient = *c
			ciliumEndpointSlice = ces
			pod = podResource
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pod, ciliumEndpointSlice, cesMetrics)
	podStore, _ := pod.Store(context.Background())

	var createdSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	pod1 := tu.CreateStorePod("pod1", "ns", 1)
	podStore.CacheStore().Add(pod1)
	pod2 := tu.CreateStorePod("pod2", "ns", 2)
	podStore.CacheStore().Add(pod2)
	pod3 := tu.CreateStorePod("pod3", "ns", 2)
	podStore.CacheStore().Add(pod3)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("pod1", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("pod2", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("pod3", "ns"), CESName("ces2"))
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Equal(t, 2, len(createdSlice.Endpoints))
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "pod1")
	assert.Contains(t, eps, "pod2")

	hive.Stop(tlog, context.Background())
}

func TestReconcileUpdate(t *testing.T) {
	var r *reconciler
	var fakeClient k8sClient.FakeClientset
	m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
	var pod resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			podResource resource.Resource[*slim_corev1.Pod],
			metrics *Metrics,
		) error {
			fakeClient = *c
			ciliumEndpointSlice = ces
			pod = podResource
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pod, ciliumEndpointSlice, cesMetrics)
	podStore, _ := pod.Store(context.Background())
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	var updatedSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updatedSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})
	pod1 := tu.CreateStorePod("pod1", "ns", 1)
	podStore.CacheStore().Add(pod1)
	pod2 := tu.CreateStorePod("pod2", "ns", 2)
	podStore.CacheStore().Add(pod2)
	pod3 := tu.CreateStorePod("pod3", "ns", 2)
	podStore.CacheStore().Add(pod3)
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("pod1", 1), tu.CreateManagerEndpoint("pod3", 2)})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("pod1", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("pod2", "ns"), CESName("ces1"))
	m.mapping.insertCEP(NewCEPName("pod3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to cep1 and cep2
	// so it's expected that after update it would contain cep1 and cep2
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", updatedSlice.Name)
	assert.Equal(t, 2, len(updatedSlice.Endpoints))
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "pod1")
	assert.Contains(t, eps, "pod2")

	hive.Stop(tlog, context.Background())
}

func TestReconcileDelete(t *testing.T) {
	var r *reconciler
	var fakeClient k8sClient.FakeClientset
	m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
	var pod resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			podResource resource.Resource[*slim_corev1.Pod],
			metrics *Metrics,
		) error {
			fakeClient = *c
			ciliumEndpointSlice = ces
			pod = podResource
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pod, ciliumEndpointSlice, cesMetrics)
	podStore, _ := pod.Store(context.Background())
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())

	var deletedSlice string
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deletedSlice = pa.GetName()
		return true, nil, nil
	})

	pod1 := tu.CreateStorePod("pod1", "ns", 1)
	podStore.CacheStore().Add(pod1)
	pod2 := tu.CreateStorePod("pod2", "ns", 2)
	podStore.CacheStore().Add(pod2)
	pod3 := tu.CreateStorePod("pod3", "ns", 2)
	podStore.CacheStore().Add(pod3)
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("pod1", 1), tu.CreateManagerEndpoint("pod3", 2)})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("pod1", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("pod2", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("pod3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", deletedSlice)

	hive.Stop(tlog, context.Background())
}

func TestReconcileNoop(t *testing.T) {
	var r *reconciler
	var fakeClient k8sClient.FakeClientset
	m := newCESManagerFcfs(2, log).(*cesManagerFcfs)
	var pod resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			podResource resource.Resource[*slim_corev1.Pod],
			metrics *Metrics,
		) error {
			fakeClient = *c
			ciliumEndpointSlice = ces
			pod = podResource
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pod, ciliumEndpointSlice, cesMetrics)
	podStore, _ := pod.Store(context.Background())

	noRequest := true
	fakeClient.CiliumFakeClientset.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		noRequest = false
		return true, nil, nil
	})

	pod1 := tu.CreateStorePod("pod1", "ns", 1)
	podStore.CacheStore().Add(pod1)
	pod2 := tu.CreateStorePod("pod2", "ns", 2)
	podStore.CacheStore().Add(pod2)
	pod3 := tu.CreateStorePod("pod3", "ns", 2)
	podStore.CacheStore().Add(pod3)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("pod1", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("pod2", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("pod3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, true, noRequest)

	hive.Stop(tlog, context.Background())
}
