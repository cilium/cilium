// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	cidtest "github.com/cilium/cilium/operator/pkg/ciliumidentity/testutils"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/metrics"
)

func TestReconcileCreateDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	r = newDefaultReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(t.Context())

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
	assert.Len(t, createdSlice.Endpoints, 2)
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileUpdateDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	r = newDefaultReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())

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
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1, "node1"), tu.CreateManagerEndpoint("cep3", 2, "node2")})
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
	assert.Len(t, updatedSlice.Endpoints, 2)
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "cep1")
	assert.Contains(t, eps, "cep2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileDeleteDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	r = newDefaultReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())

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
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1, "node1"), tu.CreateManagerEndpoint("cep3", 2, "node3")})
	cesStore.CacheStore().Add(ces1)
	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	m.mapping.insertCEP(NewCEPName("cep1", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep2", "ns"), CESName("ces2"))
	m.mapping.insertCEP(NewCEPName("cep3", "ns"), CESName("ces2"))
	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", deletedSlice)

	hive.Stop(tlog, t.Context())
}

func TestReconcileNoopDefault(t *testing.T) {
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, hivetest.Logger(t))
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cep resource.Resource[*cilium_v2.CiliumEndpoint],
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			ciliumEndpoint = cep
			ciliumEndpointSlice = ces
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	r = newDefaultReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cepStore, _ := ciliumEndpoint.Store(t.Context())

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

	assert.True(t, noRequest)

	hive.Stop(tlog, t.Context())
}

func TestReconcileCreate(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	labelsfilter.ParseLabelPrefixCfg(tlog, nil, nil, "")

	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	var createdSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createdSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)

	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)

	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsC, "node1")
	podStore.CacheStore().Add(pod3)
	cid3 := cidtest.NewCIDWithNamespace("3", pod3, ns1)
	cidStore.CacheStore().Add(cid3)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")

	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	_, gidC := cidToGidLabels(cid3)

	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.insertCID("3", gidC)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces1"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces1"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidC)

	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", createdSlice.Name)
	assert.Len(t, createdSlice.Endpoints, 2)
	assert.Equal(t, "ns", createdSlice.Namespace)
	eps := []string{createdSlice.Endpoints[0].Name, createdSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "pod1")
	assert.Contains(t, eps, "pod2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileUpdate(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)
	podStore, _ := pods.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	var updatedSlice *cilium_v2a1.CiliumEndpointSlice
	fakeClient.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updatedSlice = pa.GetObject().(*cilium_v2a1.CiliumEndpointSlice)
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)

	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)

	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod3)

	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("pod1", 1, "node1"), tu.CreateManagerEndpoint("pod3", 2, "node1")})
	cesStore.CacheStore().Add(ces1)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")

	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces1"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces1"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidB)

	// ces1 contains cep1 and cep3, but it's mapped to cep1 and cep2
	// so it's expected that after update it would contain cep1 and cep2
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", updatedSlice.Name)
	assert.Len(t, updatedSlice.Endpoints, 2)
	assert.Equal(t, "ns", updatedSlice.Namespace)
	eps := []string{updatedSlice.Endpoints[0].Name, updatedSlice.Endpoints[1].Name}
	assert.Contains(t, eps, "pod1")
	assert.Contains(t, eps, "pod2")

	hive.Stop(tlog, t.Context())
}

func TestReconcileDelete(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)
	podStore, _ := pods.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	var deletedSlice string
	fakeClient.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deletedSlice = pa.GetName()
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)

	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)
	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod3)

	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{tu.CreateManagerEndpoint("cep1", 1, "node1"), tu.CreateManagerEndpoint("cep3", 2, "node1")})
	cesStore.CacheStore().Add(ces1)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces2"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces2"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidB)

	// ces1 contains cep1 and cep3, but it's mapped to nothing so it should be deleted
	r.reconcileCES(CESName("ces1"))

	assert.Equal(t, "ces1", deletedSlice)

	hive.Stop(tlog, t.Context())
}

func TestReconcileNoop(t *testing.T) {
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, hivetest.Logger(t))
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			cn resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			ci resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = cn
			namespace = ns
			ciliumIdentity = ci
			cesMetrics = metrics
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, hivetest.Logger(t), ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	ciliumNodeStore, _ := ciliumNode.Store(t.Context())

	noRequest := true
	fakeClient.CiliumFakeClientset.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		noRequest = false
		return true, nil, nil
	})

	node := tu.CreateStoreNode("node1")
	ciliumNodeStore.CacheStore().Add(node)
	m.mapping.insertNode(NodeName("node1"), EncryptionKey(0))

	ns1 := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns1)
	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	podStore.CacheStore().Add(pod1)
	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns1)
	cidStore.CacheStore().Add(cid1)
	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod2)
	cid2 := cidtest.NewCIDWithNamespace("2", pod2, ns1)
	cidStore.CacheStore().Add(cid2)
	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod3)

	m.mapping.insertCES(CESName("ces1"), "ns")
	m.mapping.insertCES(CESName("ces2"), "ns")
	_, gidA := cidToGidLabels(cid1)
	_, gidB := cidToGidLabels(cid2)
	m.mapping.insertCID("1", gidA)
	m.mapping.insertCID("2", gidB)
	m.mapping.addCEP(NewCEPName("pod1", "ns"), CESName("ces2"), "node1", gidA)
	m.mapping.addCEP(NewCEPName("pod2", "ns"), CESName("ces2"), "node1", gidB)
	m.mapping.addCEP(NewCEPName("pod3", "ns"), CESName("ces2"), "node1", gidB)

	// ces1 is mapped to nothing so it won't be reconciled
	r.reconcileCES(CESName("ces1"))

	assert.True(t, noRequest)

	hive.Stop(tlog, t.Context())
}
