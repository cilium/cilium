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
	cidtest "github.com/cilium/cilium/operator/pkg/ciliumidentity/testutils"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
	wgAgent "github.com/cilium/cilium/pkg/wireguard/agent"
)

func TestFCFSModeSyncCESsInLocalCacheDefault(t *testing.T) {
	log := hivetest.Logger(t)
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, log)
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
	hive.Start(log, t.Context())
	r = newDefaultReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &DefaultController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient.Clientset,
			ciliumEndpointSlice: ciliumEndpointSlice,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			doReconciler:        r,
		},
		manager:        m,
		reconciler:     r,
		ciliumEndpoint: ciliumEndpoint,
	}
	cesController.initializeQueue()

	cep1 := tu.CreateManagerEndpoint("cep1", 1, "node1")
	cep2 := tu.CreateManagerEndpoint("cep2", 1, "node2")
	cep3 := tu.CreateManagerEndpoint("cep3", 2, "node3")
	cep4 := tu.CreateManagerEndpoint("cep4", 2, "node2")
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})
	cesStore.CacheStore().Add(ces1)
	cep5 := tu.CreateManagerEndpoint("cep5", 1, "node1")
	cep6 := tu.CreateManagerEndpoint("cep6", 1, "node2")
	cep7 := tu.CreateManagerEndpoint("cep7", 2, "node3")
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
	hive.Stop(log, t.Context())
}

func TestDifferentSpeedQueuesDefault(t *testing.T) {
	log := hivetest.Logger(t)
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, log)
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
	hive.Start(log, t.Context())

	r = newDefaultReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &DefaultController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient.Clientset,
			ciliumEndpointSlice: ciliumEndpointSlice,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			metrics:             cesMetrics,
			priorityNamespaces:  make(map[string]struct{}),
			syncDelay:           0,
			doReconciler:        r,
		},
		manager:        m,
		reconciler:     r,
		ciliumEndpoint: ciliumEndpoint,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.context, cesController.contextCancel = context.WithCancel(t.Context())
	cesController.priorityNamespaces["FastNamespace"] = struct{}{}
	cesController.initializeQueue()
	var ns = "NotSoImportant"
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
	hive.Stop(log, t.Context())
}

func TestCESManagementDefault(t *testing.T) {
	log := hivetest.Logger(t)
	var r *defaultReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newDefaultManager(2, log)
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
	hive.Start(log, t.Context())

	r = newDefaultReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpoint, ciliumEndpointSlice, cesMetrics)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &DefaultController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient.Clientset,
			ciliumEndpointSlice: ciliumEndpointSlice,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			metrics:             cesMetrics,
			priorityNamespaces:  make(map[string]struct{}),
			syncDelay:           0,
			doReconciler:        r,
		},
		manager:        m,
		reconciler:     r,
		ciliumEndpoint: ciliumEndpoint,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.context, cesController.contextCancel = context.WithCancel(t.Context())
	cesController.initializeQueue()
	var ns = "ns"

	cep1 := tu.CreateStoreEndpoint(fmt.Sprintf("cep-%d", 0), ns, 0)
	cesController.onEndpointUpdate(cep1)
	if err := testutils.WaitUntil(func() bool {
		return cesController.standardQueue.Len() == 1
	}, time.Second); err != nil {
		assert.Equal(t, 1, cesController.standardQueue.Len())
	}
	cesController.processNextWorkItem()
	//A CEP is enqueued and processed. Then, the same CEP (and CES) is enqueued
	//to test if the CESStore works properly and if the associated CES can be found in the store
	cesController.onEndpointUpdate(cep1)

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
	hive.Stop(log, t.Context())
}

func TestFCFSModeSyncCESsInLocalCache(t *testing.T) {
	log := hivetest.Logger(t)
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, log)
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
		ipsec.OperatorCell,
		wgAgent.OperatorCell,
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
	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient.Clientset,
			ciliumEndpointSlice: ciliumEndpointSlice,
			ciliumNodes:         ciliumNode,
			namespace:           namespace,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			doReconciler:        r,
			metrics:             cesMetrics,
			priorityNamespaces:  make(map[string]struct{}),
		},
		ipsecEnabled:   false,
		wgEnabled:      false,
		manager:        m,
		reconciler:     r,
		pods:           pods,
		ciliumIdentity: ciliumIdentity,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.initializeQueue()

	node1 := tu.CreateStoreNode("node1")
	node2 := tu.CreateStoreNode("node2")
	nodeStore.CacheStore().Add(node1)
	nodeStore.CacheStore().Add(node2)

	ns := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns)

	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsA, "node2")
	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node2")
	pod4 := cidtest.NewPod("pod4", "ns", tu.TestLbsB, "node2")
	pod5 := cidtest.NewPod("pod5", "ns", tu.TestLbsA, "node1")
	pod6 := cidtest.NewPod("pod6", "ns", tu.TestLbsA, "node1")
	pod7 := cidtest.NewPod("pod7", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod1)
	podStore.CacheStore().Add(pod2)
	podStore.CacheStore().Add(pod3)
	podStore.CacheStore().Add(pod4)
	podStore.CacheStore().Add(pod5)
	podStore.CacheStore().Add(pod6)
	podStore.CacheStore().Add(pod7)

	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns)
	cid2 := cidtest.NewCIDWithNamespace("2", pod3, ns)
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

	cache := m.mapping

	for _, ces := range []*cilium_v2a1.CiliumEndpointSlice{ces1, ces2} {
		for _, cep := range ces.Endpoints {
			cesN, _ := cache.getCESName(NewCEPName(cep.Name, "ns"))
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
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, log)
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
		ipsec.OperatorCell,
		wgAgent.OperatorCell,
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

	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient.Clientset,
			ciliumEndpointSlice: ciliumEndpointSlice,
			ciliumNodes:         ciliumNode,
			namespace:           namespace,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			doReconciler:        r,
			metrics:             cesMetrics,
			priorityNamespaces:  make(map[string]struct{}),
		},
		ipsecEnabled:   false,
		wgEnabled:      false,
		manager:        m,
		reconciler:     r,
		pods:           pods,
		ciliumIdentity: ciliumIdentity,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.context, cesController.contextCancel = context.WithCancel(t.Context())
	cesController.priorityNamespaces["FastNamespace"] = struct{}{}
	cesController.initializeQueue()
	var ns = "NotSoImportant"
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
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, log)
	var pods resource.Resource[*slim_corev1.Pod]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
	var namespace resource.Resource[*slim_corev1.Namespace]
	var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
	var cesMetrics *Metrics
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		ipsec.OperatorCell,
		wgAgent.OperatorCell,
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

	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient.Clientset,
			ciliumEndpointSlice: ciliumEndpointSlice,
			ciliumNodes:         ciliumNode,
			namespace:           namespace,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			doReconciler:        r,
			metrics:             cesMetrics,
			priorityNamespaces:  make(map[string]struct{}),
		},
		ipsecEnabled:   false,
		wgEnabled:      false,
		manager:        m,
		reconciler:     r,
		pods:           pods,
		ciliumIdentity: ciliumIdentity,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.context, cesController.contextCancel = context.WithCancel(t.Context())
	cesController.initializeQueue()
	var ns = "ns"

	node1 := tu.CreateStoreNode("node1")
	nodeStore.CacheStore().Add(node1)
	cesController.onNodeUpdate(node1)

	nsObj := cidtest.NewNamespace(ns, nil)
	nsStore.CacheStore().Add(nsObj)
	cesController.onNamespaceUpsert(nsObj)

	pod1 := cidtest.NewPod("pod1", ns, tu.TestLbsA, "node1")

	cid := cidtest.NewCIDWithNamespace("cid1", pod1, nsObj)
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
	cesController.onNamespaceDelete(nsObj)

	cesController.fastQueue.ShutDown()
	cesController.standardQueue.ShutDown()
	hive.Stop(tlog, t.Context())
}

func TestSyncCESsInLocalCacheDeletedCID(t *testing.T) {
	log := hivetest.Logger(t)
	var r *slimReconciler
	var fakeClient *k8sClient.FakeClientset
	m := newSlimManager(2, log)
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
		ipsec.OperatorCell,
		wgAgent.OperatorCell,
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
	r = newSlimReconciler(t.Context(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, ciliumEndpointSlice, pods, ciliumIdentity, ciliumNode, namespace, cesMetrics, false, false)
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient.Clientset,
			ciliumEndpointSlice: ciliumEndpointSlice,
			ciliumNodes:         ciliumNode,
			namespace:           namespace,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			doReconciler:        r,
			metrics:             cesMetrics,
			priorityNamespaces:  make(map[string]struct{}),
		},
		ipsecEnabled:   false,
		wgEnabled:      false,
		manager:        m,
		reconciler:     r,
		pods:           pods,
		ciliumIdentity: ciliumIdentity,
	}
	cesController.cond = *sync.NewCond(&lock.Mutex{})
	cesController.initializeQueue()

	node1 := tu.CreateStoreNode("node1")
	node2 := tu.CreateStoreNode("node2")
	nodeStore.CacheStore().Add(node1)
	nodeStore.CacheStore().Add(node2)

	ns := cidtest.NewNamespace("ns", nil)
	nsStore.CacheStore().Add(ns)

	pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
	pod2 := cidtest.NewPod("pod2", "ns", tu.TestLbsA, "node2")
	pod3 := cidtest.NewPod("pod3", "ns", tu.TestLbsB, "node2")
	pod4 := cidtest.NewPod("pod4", "ns", tu.TestLbsB, "node2")
	pod5 := cidtest.NewPod("pod5", "ns", tu.TestLbsA, "node1")
	pod6 := cidtest.NewPod("pod6", "ns", tu.TestLbsA, "node1")
	pod7 := cidtest.NewPod("pod7", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod1)
	podStore.CacheStore().Add(pod2)
	podStore.CacheStore().Add(pod3)
	podStore.CacheStore().Add(pod4)
	podStore.CacheStore().Add(pod5)
	podStore.CacheStore().Add(pod6)
	podStore.CacheStore().Add(pod7)

	cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns)
	cid2 := cidtest.NewCIDWithNamespace("2", pod3, ns)
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

	// Delete CID to simulate the scenario where CID deleted during Operator restart
	cidStore.CacheStore().Delete(cid1)

	cesController.syncCESsInLocalCache(t.Context())
	// Immediately after sync, CESCache does not contain pods with CID1
	assert.NotContains(t, m.mapping.cidToGidLabels, cid1)
	for _, pod := range podStore.List() {
		if pod.Name == "pod1" || pod.Name == "pod2" || pod.Name == "pod5" || pod.Name == "pod6" {
			assert.NotContains(t, m.mapping.cepData, NewCEPName(pod.Name, "ns"))
		} else {
			assert.Contains(t, m.mapping.cepData, NewCEPName(pod.Name, "ns"))
		}
	}

	// After some time, the CESController should reprocess the CEPs
	cesController.onPodUpdate(pod1)
	cesController.onPodUpdate(pod2)
	cesController.onPodUpdate(pod5)
	cesController.onPodUpdate(pod6)
	for _, pod := range podStore.List() {
		assert.Contains(t, m.mapping.cepData, NewCEPName(pod.Name, "ns"))
	}

	cesController.fastQueue.ShutDown()
	cesController.standardQueue.ShutDown()
	hive.Stop(tlog, t.Context())
}
