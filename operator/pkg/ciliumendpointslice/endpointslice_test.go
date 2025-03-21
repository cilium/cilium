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
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestFCFSModeSyncCESsInLocalCache(t *testing.T) {
	log := hivetest.Logger(t)
	var r *reconciler
	var fakeClient *k8sClient.FakeClientset
	m := newCESManager(2, log).(*cesManager)
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
	hive.Start(tlog, context.Background())
	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pods, ciliumEndpointSlice, ciliumNode, namespace, ciliumIdentity, cesMetrics)
	cesStore, _ := ciliumEndpointSlice.Store(context.Background())
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

	cep1 := tu.CreateManagerEndpoint("cep1", 1)
	cep2 := tu.CreateManagerEndpoint("cep2", 1)
	cep3 := tu.CreateManagerEndpoint("cep3", 2)
	cep4 := tu.CreateManagerEndpoint("cep4", 2)
	ces1 := tu.CreateStoreEndpointSlice("ces1", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})
	cesStore.CacheStore().Add(ces1)
	cep5 := tu.CreateManagerEndpoint("cep5", 1)
	cep6 := tu.CreateManagerEndpoint("cep6", 1)
	cep7 := tu.CreateManagerEndpoint("cep7", 2)
	ces2 := tu.CreateStoreEndpointSlice("ces2", "ns", []cilium_v2a1.CoreCiliumEndpoint{cep5, cep6, cep7})
	cesStore.CacheStore().Add(ces2)

	cesController.syncCESsInLocalCache(context.Background())

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
	hive.Stop(tlog, context.Background())
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
	hive.Start(tlog, context.Background())

	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pods, ciliumEndpointSlice, ciliumNode, namespace, ciliumIdentity, cesMetrics)

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
	cesController.context, cesController.contextCancel = context.WithCancel(context.Background())
	cesController.priorityNamespaces["FastNamespace"] = struct{}{}
	cesController.initializeQueue()
	var ns string = "NotSoImportant"
	var standardQueueLen int
	var fastQueueLen int

	for i := 0; i < 10; i++ {
		if i == 6 {
			ns = "FastNamespace"
		}
		cep1 := tu.CreateManagerEndpoint("cep1", int64(2*i+1))
		cep2 := tu.CreateManagerEndpoint("cep2", int64(2*i))

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

	for i := 0; i < 10; i++ {
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
	hive.Stop(tlog, context.Background())
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
	hive.Start(tlog, context.Background())

	r = newReconciler(context.Background(), fakeClient.CiliumFakeClientset.CiliumV2alpha1(), m, log, pods, ciliumEndpointSlice, ciliumNode, namespace, ciliumIdentity, cesMetrics)

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
	cesController.context, cesController.contextCancel = context.WithCancel(context.Background())
	cesController.initializeQueue()
	var ns string = "ns"

	pod1 := idtu.CreatePodObj(fmt.Sprintf("pod-%d", 0), ns, nil, nil)
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
	hive.Stop(tlog, context.Background())
}
