// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"

	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	cidtest "github.com/cilium/cilium/operator/pkg/ciliumidentity/testutils"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
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
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	r = newDefaultReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cepStore, cesStore, cesMetrics)
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &DefaultController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
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
	cepStore.CacheStore().Add(tu.CreateStoreEndpoint("cep1", "ns", 1))
	cepStore.CacheStore().Add(tu.CreateStoreEndpoint("cep2", "ns", 1))
	cepStore.CacheStore().Add(tu.CreateStoreEndpoint("cep3", "ns", 2))
	cepStore.CacheStore().Add(tu.CreateStoreEndpoint("cep4", "ns", 2))
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})
	cesStore.CacheStore().Add(ces1)

	cep5 := tu.CreateManagerEndpoint("cep5", 1, "node1")
	cep6 := tu.CreateManagerEndpoint("cep6", 1, "node2")
	cep7 := tu.CreateManagerEndpoint("cep7", 2, "node3")
	cepStore.CacheStore().Add(tu.CreateStoreEndpoint("cep5", "ns", 1))
	cepStore.CacheStore().Add(tu.CreateStoreEndpoint("cep6", "ns", 1))
	// cep7 is intentionally NOT added to the CEP store, simulating a pod that
	// was deleted while the operator was down. The bootstrap must drop it from
	// the mapping.
	ces2 := tu.CreateStoreEndpointSlice("ces2", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep5, cep6, cep7})
	cesStore.CacheStore().Add(ces2)

	// Subscribe after seeding so the replay picks up the objects we injected.
	cepEvents := ciliumEndpoint.Events(t.Context())
	cesEvents := ciliumEndpointSlice.Events(t.Context())
	cesController.syncCESsInLocalCache(cepEvents, cesEvents)

	mapping := m.mapping

	for _, ces := range []*cilium_v2a1.CiliumEndpointSlice{ces1, ces2} {
		for _, cep := range ces.Endpoints {
			cesN, _ := mapping.getCESName(NewCEPName(cep.Name, "ns"))
			if cep.Name == "cep7" {
				assert.Empty(t, cesN, "stale cep7 should not have a CES mapping")
				continue
			}

			// ensure that the CEP is mapped to the correct CES
			assert.Equal(t, cesN, CESName(ces.Name))
		}
	}

	cesController.queue.ShutDown()
	hive.Stop(log, t.Context())
}

func queueLengths(t *testing.T, c *Controller) (standardQueueLen, fastQueueLen int) {
	t.Helper()

	keys := make([]CESKey, 0, c.queue.Len())
	priorities := make([]int, 0, c.queue.Len())
	for c.queue.Len() > 0 {
		key, priority, shutdown := c.queue.GetWithPriority()
		assert.False(t, shutdown)
		keys = append(keys, key)
		priorities = append(priorities, priority)
		c.queue.Done(key)

		if priority == highPriority {
			fastQueueLen++
		} else {
			standardQueueLen++
		}
	}

	for i, key := range keys {
		c.queue.AddWithOpts(priorityqueue.AddOpts{Priority: &priorities[i]}, key)
	}

	return standardQueueLen, fastQueueLen
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

	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cepStore, cesStore, cesMetrics)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &DefaultController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
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
		// Ensure that the lengths of the queues after adding an element are correct
		if err := testutils.WaitUntil(func() bool {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			return standardLen == standardQueueLen && fastLen == fastQueueLen
		}, time.Second); err != nil {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			assert.Equal(t, standardQueueLen, standardLen)
			assert.Equal(t, fastQueueLen, fastLen)
		}
	}

	for i := range 10 {
		cesController.processNextWorkItem(t.Context())
		if i < 4 {
			standardQueueLen = 6
			fastQueueLen = 3 - i
		} else {
			standardQueueLen = 6 - (i - 3)
			fastQueueLen = 0
		}
		// Ensure that the lengths of the queues after removing an element are correct
		if err := testutils.WaitUntil(func() bool {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			return standardLen == standardQueueLen && fastLen == fastQueueLen
		}, time.Second); err != nil {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			assert.Equal(t, standardQueueLen, standardLen)
			assert.Equal(t, fastQueueLen, fastLen)
		}
	}

	cesController.queue.ShutDown()
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

	cepStore, _ := ciliumEndpoint.Store(t.Context())
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	r = newDefaultReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cepStore, cesStore, cesMetrics)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &DefaultController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
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
	cesController.initializeQueue()
	var ns = "ns"

	cep1 := tu.CreateStoreEndpoint(fmt.Sprintf("cep-%d", 0), ns, 0)
	cesController.onEndpointUpdate(cep1)
	if err := testutils.WaitUntil(func() bool {
		return cesController.queue.Len() == 1
	}, time.Second); err != nil {
		assert.Equal(t, 1, cesController.queue.Len())
	}
	cesController.processNextWorkItem(t.Context())
	//A CEP is enqueued and processed. Then, the same CEP (and CES) is enqueued
	//to test if the CESStore works properly and if the associated CES can be found in the store
	cesController.onEndpointUpdate(cep1)

	key, _, _ := cesController.queue.GetWithPriority()
	if err := testutils.WaitUntil(func() bool {
		_, exists, _ := r.cesStore.GetByKey(NewCESKey(key.Name, "").key())
		return exists == true
	}, time.Second); err != nil {
		_, exists, _ := r.cesStore.GetByKey(NewCESKey(key.Name, "").key())
		assert.True(t, exists)
	}

	cesController.queue.ShutDown()
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
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
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

	cesController.syncCESsInLocalCache(ciliumNode.Events(t.Context()), ciliumIdentity.Events(t.Context()), ciliumEndpointSlice.Events(t.Context()), pods.Events(t.Context()))

	cache := m.mapping

	for _, ces := range []*cilium_v2a1.CiliumEndpointSlice{ces1, ces2} {
		for _, cep := range ces.Endpoints {
			cesN, _ := cache.getCESName(NewCEPName(cep.Name, "ns"))
			// ensure that the CEP is mapped to the correct CES
			assert.Equal(t, cesN, CESName(ces.Name))
		}
	}

	cesController.queue.ShutDown()
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

	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
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
		// Ensure that the lengths of the queues after adding an element are correct
		if err := testutils.WaitUntil(func() bool {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			return standardLen == standardQueueLen && fastLen == fastQueueLen
		}, time.Second); err != nil {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			assert.Equal(t, standardQueueLen, standardLen)
			assert.Equal(t, fastQueueLen, fastLen)
		}
	}

	for i := range 10 {
		cesController.processNextWorkItem(t.Context())
		if i < 4 {
			standardQueueLen = 6
			fastQueueLen = 3 - i
		} else {
			standardQueueLen = 6 - (i - 3)
			fastQueueLen = 0
		}
		// Ensure that the lengths of the queues after removing an element are correct
		if err := testutils.WaitUntil(func() bool {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			return standardLen == standardQueueLen && fastLen == fastQueueLen
		}, time.Second); err != nil {
			standardLen, fastLen := queueLengths(t, cesController.Controller)
			assert.Equal(t, standardQueueLen, standardLen)
			assert.Equal(t, fastQueueLen, fastLen)
		}
	}

	cesController.queue.ShutDown()
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

	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)

	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
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
		return cesController.queue.Len() == 1
	}, time.Second); err != nil {
		assert.Equal(t, 1, cesController.queue.Len())
	}
	cesController.processNextWorkItem(t.Context())
	//A CEP is enqueued and processed. Then, the same CEP (and CES) is enqueued
	//to test if the CESStore works properly and if the associated CES can be found in the store
	cesController.onPodUpdate(pod1)

	key, _, _ := cesController.queue.GetWithPriority()
	if err := testutils.WaitUntil(func() bool {
		_, exists, _ := r.cesStore.GetByKey(NewCESKey(key.Name, "").key())
		return exists == true
	}, time.Second); err != nil {
		_, exists, _ := r.cesStore.GetByKey(NewCESKey(key.Name, "").key())
		assert.True(t, exists)
	}
	cesController.onNamespaceDelete(nsObj)

	cesController.queue.ShutDown()
	hive.Stop(tlog, t.Context())
}

// TestSyncCESsInLocalCacheOperatorDowntime covers three scenarios that can
// happen while the operator is down and must be handled correctly on the
// next bootstrap:
//   - a CID is deleted → pods that used it should still be tracked but
//     their entries in cepData have no resolvable identity yet (reconciler
//     filters those at write time).
//   - a pod is deleted → its entry in the CES on the API side is stale;
//     bootstrap must skip it and mark the CES dirty so the reconciler
//     rewrites it without the deleted pod.
//   - a pod is added → it exists in the Pod store but no CES lists it yet;
//     bootstrap's phase 5 must place it into an existing CES (with room)
//     rather than creating a phantom one.
func TestSyncCESsInLocalCacheOperatorDowntime(t *testing.T) {
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
	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	nodeStore, _ := ciliumNode.Store(t.Context())
	cidStore, _ := ciliumIdentity.Store(t.Context())
	podStore, _ := pods.Store(t.Context())
	nsStore, _ := namespace.Store(t.Context())
	r = newSlimReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)
	cesController := &SlimController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
			ciliumEndpointSlice: ciliumEndpointSlice,
			ciliumNodes:         ciliumNode,
			namespace:           namespace,
			rateLimit:           rateLimitConfig,
			enqueuedAt:          make(map[CESKey]time.Time),
			doReconciler:        r,
			metrics:             cesMetrics,
			priorityNamespaces:  make(map[string]struct{}),
			syncDelay:           0,
		},
		ipsecEnabled:   false,
		wgEnabled:      false,
		manager:        m,
		reconciler:     r,
		pods:           pods,
		ciliumIdentity: ciliumIdentity,
	}
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
	// pod7 (declared inline as the CES entry below) is intentionally NOT
	// added to the Pod store, simulating a pod deleted while operator was
	// down. The CES still lists it.
	// pod8 exists in the Pod store but no CES lists it yet — simulating a
	// pod that was created while the operator was down.
	pod8 := cidtest.NewPod("pod8", "ns", tu.TestLbsB, "node1")
	podStore.CacheStore().Add(pod1)
	podStore.CacheStore().Add(pod2)
	podStore.CacheStore().Add(pod3)
	podStore.CacheStore().Add(pod4)
	podStore.CacheStore().Add(pod5)
	podStore.CacheStore().Add(pod6)
	// pod7 is intentionally NOT added to the Pod store.
	podStore.CacheStore().Add(pod8)

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

	// Delete CID1 to simulate the scenario where a CID was deleted while
	// the operator was down.
	cidStore.CacheStore().Delete(cid1)

	cesController.syncCESsInLocalCache(ciliumNode.Events(t.Context()), ciliumIdentity.Events(t.Context()), ciliumEndpointSlice.Events(t.Context()), pods.Events(t.Context()))

	// CID1 is gone from the identity mapping.
	assert.NotContains(t, m.mapping.cidToGidLabels, cid1)

	// Pods that still exist are in cepData; pod7 (deleted while down) is not.
	for _, pod := range podStore.List() {
		assert.Contains(t, m.mapping.cepData, NewCEPName(pod.Name, "ns"))
	}
	assert.NotContains(t, m.mapping.cepData, NewCEPName("pod7", "ns"))

	// pod8 (added while down) was placed in some CES via phase 5's
	// onPodUpdate — either into an existing CES with capacity or a fresh
	// one if none had room.
	_, ok := m.mapping.getCESName(NewCEPName("pod8", "ns"))
	assert.True(t, ok, "pod8 should be placed in a CES")

	// Some CES(es) should have been enqueued for reconciliation:
	// - ces2 because pod7 was skipped as stale.
	// - the CES that received pod8 (via onPodUpdate's enqueue).
	if err := testutils.WaitUntil(func() bool {
		return cesController.queue.Len() >= 1
	}, time.Second); err != nil {
		t.Fatalf("expected CES(es) to be enqueued after bootstrap; queues empty")
	}

	// Calling onPodUpdate again is idempotent for already-placed pods.
	cesController.onPodUpdate(pod1)
	cesController.onPodUpdate(pod2)
	cesController.onPodUpdate(pod5)
	cesController.onPodUpdate(pod6)
	for _, pod := range podStore.List() {
		assert.Contains(t, m.mapping.cepData, NewCEPName(pod.Name, "ns"))
	}

	cesController.queue.ShutDown()
	hive.Stop(tlog, t.Context())
}

func TestDefaultController_SyncCESsInLocalCache_ServiceAccount(t *testing.T) {
	tests := []struct {
		name           string
		enableZTunnel  bool
		cesSA          string
		liveSA         string
		expectEnqueued bool
		expectedCESSA  string
	}{
		{
			name:           "case a: EnableZTunnel=true, CES endpoint has empty SA, live CEP has SA -> CES enqueued",
			enableZTunnel:  true,
			cesSA:          "",
			liveSA:         "test-sa",
			expectEnqueued: true,
			expectedCESSA:  "test-sa",
		},
		{
			name:           "case b: EnableZTunnel=false, CES endpoint has SA -> NOW enqueued",
			enableZTunnel:  false,
			cesSA:          "test-sa",
			liveSA:         "test-sa",
			expectEnqueued: true,
			expectedCESSA:  "",
		},
		{
			name:           "case c: EnableZTunnel=true, CES endpoint already has matching SA -> NOT enqueued",
			enableZTunnel:  true,
			cesSA:          "test-sa",
			liveSA:         "test-sa",
			expectEnqueued: false,
		},
		{
			name:           "case d: EnableZTunnel=false, CES endpoint without SA -> NOT enqueued",
			enableZTunnel:  false,
			cesSA:          "",
			liveSA:         "test-sa",
			expectEnqueued: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedCfg := SharedConfig{
				EnableZTunnel: tt.enableZTunnel,
			}
			log := hivetest.Logger(t)
			var fakeClient *k8sClient.FakeClientset
			var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
			var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
			var cesMetrics *Metrics
			m := newDefaultManager(2, log)
			h := hive.New(
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
			h.Start(log, t.Context())
			defer h.Stop(log, t.Context())

			cesStore, _ := ciliumEndpointSlice.Store(t.Context())
			cepStore, _ := ciliumEndpoint.Store(t.Context())
			r := newDefaultReconciler(sharedCfg, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cepStore, cesStore, cesMetrics)
			rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
			assert.NoError(t, err)

			cesController := &DefaultController{
				Controller: &Controller{
					logger:              log,
					clientset:           fakeClient,
					ciliumEndpointSlice: ciliumEndpointSlice,
					rateLimit:           rateLimitConfig,
					enqueuedAt:          make(map[CESKey]time.Time),
					metrics:             cesMetrics,
					priorityNamespaces:  make(map[string]struct{}),
					syncDelay:           0,
					doReconciler:        r,
					sharedCfg:           sharedCfg,
				},
				manager:        m,
				reconciler:     r,
				ciliumEndpoint: ciliumEndpoint,
			}
			cesController.initializeQueue()
			defer cesController.queue.ShutDown()

			const ns = "ns"
			liveCEP := tu.CreateStoreEndpoint("cep1", ns, 1)
			liveCEP.Status.ServiceAccount = tt.liveSA
			cepStore.CacheStore().Add(liveCEP)

			desired := r.getCoreEndpointFromStore(NewCEPName("cep1", ns))
			assert.NotNil(t, desired)
			ccep := *desired
			ccep.ServiceAccount = tt.cesSA
			cesObj := tu.CreateStoreEndpointSlice("ces1", ns, []cilium_v2a1.CoreCiliumEndpoint{ccep})
			cesStore.CacheStore().Add(cesObj)
			_, err = fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), cesObj, meta_v1.CreateOptions{})
			assert.NoError(t, err)

			cepEvents := ciliumEndpoint.Events(t.Context())
			cesEvents := ciliumEndpointSlice.Events(t.Context())
			err = cesController.syncCESsInLocalCache(cepEvents, cesEvents)
			assert.NoError(t, err)

			if tt.expectEnqueued {
				assert.Equal(t, 1, cesController.queue.Len())
				processed := cesController.processNextWorkItem(t.Context())
				assert.True(t, processed)

				updatedCES, err := fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Get(t.Context(), "ces1", meta_v1.GetOptions{})
				assert.NoError(t, err)
				assert.Len(t, updatedCES.Endpoints, 1)
				assert.Equal(t, tt.expectedCESSA, updatedCES.Endpoints[0].ServiceAccount)
			} else {
				assert.Equal(t, 0, cesController.queue.Len())
			}
		})
	}
}

func TestSlimController_SyncCESsInLocalCache_ServiceAccount(t *testing.T) {
	tests := []struct {
		name           string
		enableZTunnel  bool
		cesSA          string
		liveSA         string
		expectEnqueued bool
		expectedCESSA  string
	}{
		{
			name:           "case a: EnableZTunnel=true, CES endpoint has empty SA, live Pod has SA -> CES enqueued",
			enableZTunnel:  true,
			cesSA:          "",
			liveSA:         "test-sa",
			expectEnqueued: true,
			expectedCESSA:  "test-sa",
		},
		{
			name:           "case b: EnableZTunnel=false, CES endpoint has SA -> NOW enqueued",
			enableZTunnel:  false,
			cesSA:          "test-sa",
			liveSA:         "test-sa",
			expectEnqueued: true,
			expectedCESSA:  "",
		},
		{
			name:           "case c: EnableZTunnel=true, CES endpoint already has matching SA -> NOT enqueued",
			enableZTunnel:  true,
			cesSA:          "test-sa",
			liveSA:         "test-sa",
			expectEnqueued: false,
		},
		{
			name:           "case d: EnableZTunnel=false, CES endpoint without SA -> NOT enqueued",
			enableZTunnel:  false,
			cesSA:          "",
			liveSA:         "test-sa",
			expectEnqueued: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedCfg := SharedConfig{
				EnableZTunnel: tt.enableZTunnel,
			}
			log := hivetest.Logger(t)
			var fakeClient *k8sClient.FakeClientset
			var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
			var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
			var namespace resource.Resource[*slim_corev1.Namespace]
			var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
			var pods resource.Resource[*slim_corev1.Pod]
			var cesMetrics *Metrics
			m := newSlimManager(2, log)
			h := hive.New(
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
			h.Start(log, t.Context())
			defer h.Stop(log, t.Context())

			labelsfilter.ParseLabelPrefixCfg(log, nil, nil, "")
			cesStore, _ := ciliumEndpointSlice.Store(t.Context())
			nodeStore, _ := ciliumNode.Store(t.Context())
			cidStore, _ := ciliumIdentity.Store(t.Context())
			podStore, _ := pods.Store(t.Context())
			nsStore, _ := namespace.Store(t.Context())
			r := newSlimReconciler(sharedCfg, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
			rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
			assert.NoError(t, err)

			cesController := &SlimController{
				Controller: &Controller{
					logger:              log,
					clientset:           fakeClient,
					ciliumEndpointSlice: ciliumEndpointSlice,
					ciliumNodes:         ciliumNode,
					namespace:           namespace,
					rateLimit:           rateLimitConfig,
					enqueuedAt:          make(map[CESKey]time.Time),
					metrics:             cesMetrics,
					priorityNamespaces:  make(map[string]struct{}),
					syncDelay:           0,
					doReconciler:        r,
					sharedCfg:           sharedCfg,
				},
				ipsecEnabled:   false,
				wgEnabled:      false,
				manager:        m,
				reconciler:     r,
				pods:           pods,
				ciliumIdentity: ciliumIdentity,
			}
			cesController.initializeQueue()
			defer cesController.queue.ShutDown()

			node1 := tu.CreateStoreNode("node1")
			nodeStore.CacheStore().Add(node1)

			ns := cidtest.NewNamespace("ns", nil)
			nsStore.CacheStore().Add(ns)

			pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
			pod1.Spec.ServiceAccountName = tt.liveSA
			podStore.CacheStore().Add(pod1)

			cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns)
			cidStore.CacheStore().Add(cid1)

			netw, err := GetPodEndpointNetworking(pod1)
			assert.NoError(t, err)
			ccep := cilium_v2a1.CoreCiliumEndpoint{
				Name:           "pod1",
				IdentityID:     1,
				PodUID:         string(pod1.UID),
				Networking:     netw,
				Encryption:     cilium_v2.EncryptionSpec{Key: 0},
				NamedPorts:     r.getNamedPorts(pod1),
				ServiceAccount: tt.cesSA,
			}
			ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{ccep})
			cesStore.CacheStore().Add(ces1)
			_, err = fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces1, meta_v1.CreateOptions{})
			assert.NoError(t, err)

			err = cesController.syncCESsInLocalCache(ciliumNode.Events(t.Context()), ciliumIdentity.Events(t.Context()), ciliumEndpointSlice.Events(t.Context()), pods.Events(t.Context()))
			assert.NoError(t, err)

			if tt.expectEnqueued {
				assert.Equal(t, 1, cesController.queue.Len())
				processed := cesController.processNextWorkItem(t.Context())
				assert.True(t, processed)

				updatedCES, err := fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Get(t.Context(), "ces1", meta_v1.GetOptions{})
				assert.NoError(t, err)
				assert.Len(t, updatedCES.Endpoints, 1)
				assert.Equal(t, tt.expectedCESSA, updatedCES.Endpoints[0].ServiceAccount)
			} else {
				assert.Equal(t, 0, cesController.queue.Len())
			}
		})
	}
}

func TestDefaultController_SyncCESsInLocalCache_GenericDrift(t *testing.T) {
	log := hivetest.Logger(t)
	var fakeClient *k8sClient.FakeClientset
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	var cesMetrics *Metrics
	m := newDefaultManager(2, log)
	h := hive.New(
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
	h.Start(log, t.Context())
	defer h.Stop(log, t.Context())

	cesStore, _ := ciliumEndpointSlice.Store(t.Context())
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	r := newDefaultReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cepStore, cesStore, cesMetrics)
	rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
	assert.NoError(t, err)

	cesController := &DefaultController{
		Controller: &Controller{
			logger:              log,
			clientset:           fakeClient,
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
	cesController.initializeQueue()
	defer cesController.queue.ShutDown()

	const ns = "ns"
	const liveID = int64(100)
	const storedID = int64(200)

	// Live CEP has identity ID 100 (simulating identity changed while operator was down)
	liveCEP := tu.CreateStoreEndpoint("cep1", ns, liveID)
	cepStore.CacheStore().Add(liveCEP)

	// Stored CES has the old identity ID 200
	desired := r.getCoreEndpointFromStore(NewCEPName("cep1", ns))
	assert.NotNil(t, desired)
	storedCEP := *desired
	storedCEP.IdentityID = storedID

	cesObj := tu.CreateStoreEndpointSlice("ces1", ns, []cilium_v2a1.CoreCiliumEndpoint{storedCEP})
	cesStore.CacheStore().Add(cesObj)
	_, err = fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), cesObj, meta_v1.CreateOptions{})
	assert.NoError(t, err)

	cepEvents := ciliumEndpoint.Events(t.Context())
	cesEvents := ciliumEndpointSlice.Events(t.Context())
	err = cesController.syncCESsInLocalCache(cepEvents, cesEvents)
	assert.NoError(t, err)

	// Drift detected: CES must be enqueued
	assert.Equal(t, 1, cesController.queue.Len())
	processed := cesController.processNextWorkItem(t.Context())
	assert.True(t, processed)

	// Updated CES written to fake clientset must carry the live identity ID (100)
	updatedCES, err := fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Get(t.Context(), "ces1", meta_v1.GetOptions{})
	assert.NoError(t, err)
	assert.Len(t, updatedCES.Endpoints, 1)
	assert.Equal(t, liveID, updatedCES.Endpoints[0].IdentityID)
}

func TestSlimController_SyncCESsInLocalCache_GenericDrift(t *testing.T) {
	// In slim mode, the pod's identity is resolved from the local cache, which is
	// seeded during bootstrap from the CES itself (initializeMappingPodToNode).
	// Therefore, identity ID drift between a live Pod and a CES is not directly
	// observable at bootstrap.
	// However, other fields such as NamedPorts and PodUID are read directly from
	// the live Pod object and detect generic drift during bootstrap.

	tests := []struct {
		name          string
		modifyLivePod func(pod *slim_corev1.Pod)
		modifyStored  func(ccep *cilium_v2a1.CoreCiliumEndpoint)
		verifyUpdate  func(t *testing.T, ep cilium_v2a1.CoreCiliumEndpoint)
	}{
		{
			name: "named ports drift: live pod has updated container ports -> CES enqueued and updated",
			modifyLivePod: func(pod *slim_corev1.Pod) {
				pod.Spec.Containers = []slim_corev1.Container{
					{
						Name: "web",
						Ports: []slim_corev1.ContainerPort{
							{
								Name:          "http",
								ContainerPort: 8080,
								Protocol:      slim_corev1.ProtocolTCP,
							},
						},
					},
				}
			},
			modifyStored: func(ccep *cilium_v2a1.CoreCiliumEndpoint) {
				ccep.NamedPorts = nil
			},
			verifyUpdate: func(t *testing.T, ep cilium_v2a1.CoreCiliumEndpoint) {
				assert.Len(t, ep.NamedPorts, 1)
				assert.Equal(t, "http", ep.NamedPorts[0].Name)
				assert.Equal(t, uint16(8080), ep.NamedPorts[0].Port)
			},
		},
		{
			name: "pod UID drift: live pod has new UID -> CES enqueued and updated",
			modifyLivePod: func(pod *slim_corev1.Pod) {
				pod.UID = "new-pod-uid"
			},
			modifyStored: func(ccep *cilium_v2a1.CoreCiliumEndpoint) {
				ccep.PodUID = "old-pod-uid"
			},
			verifyUpdate: func(t *testing.T, ep cilium_v2a1.CoreCiliumEndpoint) {
				assert.Equal(t, "new-pod-uid", ep.PodUID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := hivetest.Logger(t)
			var fakeClient *k8sClient.FakeClientset
			var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
			var ciliumNode resource.Resource[*cilium_v2.CiliumNode]
			var namespace resource.Resource[*slim_corev1.Namespace]
			var ciliumIdentity resource.Resource[*cilium_v2.CiliumIdentity]
			var pods resource.Resource[*slim_corev1.Pod]
			var cesMetrics *Metrics
			m := newSlimManager(2, log)
			h := hive.New(
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
			h.Start(log, t.Context())
			defer h.Stop(log, t.Context())

			labelsfilter.ParseLabelPrefixCfg(log, nil, nil, "")
			cesStore, _ := ciliumEndpointSlice.Store(t.Context())
			nodeStore, _ := ciliumNode.Store(t.Context())
			cidStore, _ := ciliumIdentity.Store(t.Context())
			podStore, _ := pods.Store(t.Context())
			nsStore, _ := namespace.Store(t.Context())
			r := newSlimReconciler(SharedConfig{}, fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, cmtypes.DefaultClusterInfo, cesStore, podStore, cidStore, nodeStore, nsStore, cesMetrics, false, false)
			rateLimitConfig, err := getRateLimitConfig(params{Cfg: defaultConfig})
			assert.NoError(t, err)

			cesController := &SlimController{
				Controller: &Controller{
					logger:              log,
					clientset:           fakeClient,
					ciliumEndpointSlice: ciliumEndpointSlice,
					ciliumNodes:         ciliumNode,
					namespace:           namespace,
					rateLimit:           rateLimitConfig,
					enqueuedAt:          make(map[CESKey]time.Time),
					metrics:             cesMetrics,
					priorityNamespaces:  make(map[string]struct{}),
					syncDelay:           0,
					doReconciler:        r,
				},
				ipsecEnabled:   false,
				wgEnabled:      false,
				manager:        m,
				reconciler:     r,
				pods:           pods,
				ciliumIdentity: ciliumIdentity,
			}
			cesController.initializeQueue()
			defer cesController.queue.ShutDown()

			node1 := tu.CreateStoreNode("node1")
			nodeStore.CacheStore().Add(node1)

			ns := cidtest.NewNamespace("ns", nil)
			nsStore.CacheStore().Add(ns)

			pod1 := cidtest.NewPod("pod1", "ns", tu.TestLbsA, "node1")
			tt.modifyLivePod(pod1)
			podStore.CacheStore().Add(pod1)

			cid1 := cidtest.NewCIDWithNamespace("1", pod1, ns)
			cidStore.CacheStore().Add(cid1)

			netw, err := GetPodEndpointNetworking(pod1)
			assert.NoError(t, err)
			ccep := cilium_v2a1.CoreCiliumEndpoint{
				Name:           "pod1",
				IdentityID:     1,
				PodUID:         string(pod1.UID),
				Networking:     netw,
				Encryption:     cilium_v2.EncryptionSpec{Key: 0},
				NamedPorts:     r.getNamedPorts(pod1),
				ServiceAccount: "",
			}
			tt.modifyStored(&ccep)

			ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{ccep})
			cesStore.CacheStore().Add(ces1)
			_, err = fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), ces1, meta_v1.CreateOptions{})
			assert.NoError(t, err)

			err = cesController.syncCESsInLocalCache(ciliumNode.Events(t.Context()), ciliumIdentity.Events(t.Context()), ciliumEndpointSlice.Events(t.Context()), pods.Events(t.Context()))
			assert.NoError(t, err)

			assert.Equal(t, 1, cesController.queue.Len())
			processed := cesController.processNextWorkItem(t.Context())
			assert.True(t, processed)

			updatedCES, err := fakeClient.CiliumFakeClientset.CiliumV2alpha1().CiliumEndpointSlices().Get(t.Context(), "ces1", meta_v1.GetOptions{})
			assert.NoError(t, err)
			assert.Len(t, updatedCES.Endpoints, 1)
			tt.verifyUpdate(t, updatedCES.Endpoints[0])
		})
	}
}
