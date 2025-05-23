// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	idtu "github.com/cilium/cilium/operator/pkg/ciliumidentity/testutils"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestFCFSModeSyncCESsInLocalCache(t *testing.T) {
	log := hivetest.Logger(t)
	var r *reconciler
	var fakeClient *k8sClient.FakeClientset
	m := newCESManager(2, log)
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			node resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			identity resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = node
			namespace = ns
			ciliumIdentity = identity
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	labelsfilter.ParseLabelPrefixCfg(tlog, nil, nil, "")
	r = newReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pods, ciliumEndpointSlice, ciliumNode, namespace, ciliumIdentity, cesMetrics)
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &Controller{
		logger:              log,
		clientset:           fakeClient.Clientset,
		pods:                pods,
		ciliumEndpointSlice: ciliumEndpointSlice,
		ciliumNodes:         ciliumNode,
		namespace:           namespace,
		ciliumIdentity:      ciliumIdentity,
		reconciler:          r,
		manager:             m,
		rateLimit:           rateLimitConfig,
		enqueuedAt:          make(map[CESKey]time.Time),
	}
	cesController.initializeQueue()

	node1 := tu.CreateStoreNode("node1")
	node2 := tu.CreateStoreNode("node2")
	nodeStore.CacheStore().Add(node1)
	nodeStore.CacheStore().Add(node2)

	ns := idtu.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns)

	pod1 := idtu.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	pod2 := idtu.NewPod("pod2", "ns", tu.TestLbsA, "node2")
	pod3 := idtu.NewPod("pod3", "ns", tu.TestLbsB, "node2")
	pod4 := idtu.NewPod("pod4", "ns", tu.TestLbsB, "node2")
	pod5 := idtu.NewPod("pod5", "ns", tu.TestLbsA, "node1")
	pod6 := idtu.NewPod("pod6", "ns", tu.TestLbsA, "node1")
	pod7 := idtu.NewPod("pod7", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod1)
	podStore.CacheStore().Add(pod2)
	podStore.CacheStore().Add(pod3)
	podStore.CacheStore().Add(pod4)
	podStore.CacheStore().Add(pod5)
	podStore.CacheStore().Add(pod6)
	podStore.CacheStore().Add(pod7)

	cid1 := idtu.NewCIDWithNamespace("1", pod1, ns)
	cid2 := idtu.NewCIDWithNamespace("2", pod3, ns)
	cidStore.CacheStore().Add(cid1)
	cidStore.CacheStore().Add(cid2)

	cep1 := tu.CreateManagerEndpoint("pod1", 1, "node1")
	cep2 := tu.CreateManagerEndpoint("pod2", 1, "node2")
	cep3 := tu.CreateManagerEndpoint("pod3", 2, "node2")
	cep4 := tu.CreateManagerEndpoint("pod4", 2, "node2")
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})
	cesStore.CacheStore().Add(ces1)
	cep5 := tu.CreateManagerEndpoint("pod5", 1, "node1")
	cep6 := tu.CreateManagerEndpoint("pod6", 1, "node1")
	cep7 := tu.CreateManagerEndpoint("pod7", 2, "node1")
	ces2 := tu.CreateStoreEndpointSlice("ces2", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep5, cep6, cep7})
	cesStore.CacheStore().Add(ces2)

	cesController.syncCESsInLocalCache(t.Context())

	mapping := m.mapping

	for _, ces := range []*cilium_v2a1.CiliumEndpointSlice{ces1, ces2} {
		for _, cep := range ces.Endpoints {
			cesN, _ := mapping.getCESName(NewCEPName(cep.Name, "ns"))
			// ensure that the CEP is mapped to the correct CES
			assert.Equal(t, cesN, CESName(ces.Name))
		}
	}

	cesController.fastQueue.ShutDown()
	cesController.standardQueue.ShutDown()
	hive.Stop(tlog, t.Context())
}

func TestDifferentSpeedQueues(t *testing.T) {
	log := hivetest.Logger(t)
	var r *reconciler
	var fakeClient *k8sClient.FakeClientset
	m := newCESManager(2, log)
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			node resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			identity resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = node
			namespace = ns
			ciliumIdentity = identity
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	labelsfilter.ParseLabelPrefixCfg(tlog, nil, nil, "")

	r = newReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pods, ciliumEndpointSlice, ciliumNode, namespace, ciliumIdentity, cesMetrics)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &Controller{
		logger:              log,
		clientset:           fakeClient.Clientset,
		pods:                pods,
		ciliumEndpointSlice: ciliumEndpointSlice,
		ciliumNodes:         ciliumNode,
		namespace:           namespace,
		ciliumIdentity:      ciliumIdentity,
		reconciler:          r,
		manager:             m,
		rateLimit:           rateLimitConfig,
		enqueuedAt:          make(map[CESKey]time.Time),
		metrics:             cesMetrics,
		priorityNamespaces:  make(map[string]struct{}),
		syncDelay:           0,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.context, cesController.contextCancel = context.WithCancel(t.Context())
	cesController.priorityNamespaces["FastNamespace"] = struct{}{}
	cesController.initializeQueue()
	var ns string = "NotSoImportant"
	var standardQueueLen int
	var fastQueueLen int

	for i := range 10 {
		if i == 6 {
			ns = "FastNamespace"
		}
		cep1 := tu.CreateManagerEndpoint("cep1", int64(2*i+1), "node1")
		cep2 := tu.CreateManagerEndpoint("cep2", int64(2*i), "node1")

		ces := tu.CreateStoreEndpointSlice(fmt.Sprintf("ces-%d", i), ns, []cilium_v2a1.CoreCiliumEndpoint{cep1, cep2})

		cesController.onSliceUpdate(ces)
		if i < 6 {
			standardQueueLen = i + 1
			fastQueueLen = 0
		} else {
			standardQueueLen = 6
			fastQueueLen = i - 5
		}
		//Ensure that the lengths of the queues after adding an element are correct
		if err := testutils.WaitUntil(func() bool {
			return cesController.standardQueue.Len() == standardQueueLen && cesController.fastQueue.Len() == fastQueueLen
		}, time.Second); err != nil {
			assert.Equal(t, standardQueueLen, cesController.standardQueue.Len())
			assert.Equal(t, fastQueueLen, cesController.fastQueue.Len())
		}
	}

	for i := range 10 {
		cesController.processNextWorkItem()
		if i < 4 {
			standardQueueLen = 6
			fastQueueLen = 3 - i
		} else {
			standardQueueLen = 6 - (i - 3)
			fastQueueLen = 0
		}
		//Ensure that the lengths of the queues after removing an element are correct
		if err := testutils.WaitUntil(func() bool {
			return cesController.standardQueue.Len() == standardQueueLen && cesController.fastQueue.Len() == fastQueueLen
		}, time.Second); err != nil {
			assert.Equal(t, standardQueueLen, cesController.standardQueue.Len())
			assert.Equal(t, fastQueueLen, cesController.fastQueue.Len())
		}
	}

	cesController.fastQueue.ShutDown()
	cesController.standardQueue.ShutDown()
	hive.Stop(tlog, t.Context())
}

func TestCESManagement(t *testing.T) {
	log := hivetest.Logger(t)
	var r *reconciler
	var fakeClient *k8sClient.FakeClientset
	m := newCESManager(2, log)
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			p resource.Resource[*slim_corev1.Pod],
			ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
			node resource.Resource[*cilium_v2.CiliumNode],
			ns resource.Resource[*slim_corev1.Namespace],
			identity resource.Resource[*cilium_v2.CiliumIdentity],
			metrics *Metrics,
		) error {
			fakeClient = c
			pods = p
			ciliumEndpointSlice = ces
			ciliumNode = node
			namespace = ns
			ciliumIdentity = identity
			cesMetrics = metrics
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	hive.Start(tlog, t.Context())
	labelsfilter.ParseLabelPrefixCfg(tlog, nil, nil, "")

	r = newReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pods, ciliumEndpointSlice, ciliumNode, namespace, ciliumIdentity, cesMetrics)
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &Controller{
		logger:              log,
		clientset:           fakeClient.Clientset,
		pods:                pods,
		ciliumEndpointSlice: ciliumEndpointSlice,
		ciliumNodes:         ciliumNode,
		namespace:           namespace,
		ciliumIdentity:      ciliumIdentity,
		reconciler:          r,
		manager:             m,
		rateLimit:           rateLimitConfig,
		enqueuedAt:          make(map[CESKey]time.Time),
		metrics:             cesMetrics,
		priorityNamespaces:  make(map[string]struct{}),
		syncDelay:           0,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.context, cesController.contextCancel = context.WithCancel(t.Context())
	cesController.initializeQueue()

	node1 := tu.CreateStoreNode("node1")
	nodeStore.CacheStore().Add(node1)
	cesController.onNodeUpdate(node1)

	ns := idtu.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns)
	cesController.onNamespaceUpsert(ns)

	pod1 := idtu.NewPod("pod1", "ns", tu.TestLbsA, "node1")

	cid := idtu.NewCIDWithNamespace("cid1", pod1, ns)
	cidStore.CacheStore().Add(cid)
	cesController.onIdentityUpdate(cid)

	cesController.onPodUpdate(pod1)
	if err := testutils.WaitUntil(func() bool {
		return cesController.standardQueue.Len() == 1
	}, time.Second); err != nil {
		assert.Equal(t, 1, cesController.standardQueue.Len())
	}
	cesController.processNextWorkItem()
	//A CEP is enqueued and processed. Then, the same CEP (and CES) is enqueued
	//to test if the CESStore works properly and if the associated CES can be found in the store
	cesController.onPodUpdate(pod1)

	queue := cesController.getQueue()
	key, _ := queue.Get()
	if err := testutils.WaitUntil(func() bool {
		_, exists, _ := r.cesStore.GetByKey(NewCESKey(key.Name, "").key())
		return exists == true
	}, time.Second); err != nil {
		_, exists, _ := r.cesStore.GetByKey(NewCESKey(key.Name, "").key())
		assert.True(t, exists)
	}

	cesController.fastQueue.ShutDown()
	cesController.standardQueue.ShutDown()
	hive.Stop(tlog, t.Context())
}
