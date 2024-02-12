// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"strconv"
	"testing"

	"github.com/cilium/cilium/operator/k8s"
	cestest "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/idpool"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	idbackend "github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"
)

var (
	log                         = logging.DefaultLogger.WithField(logfields.LogSubsys, "cid-controller")
	testLabelsFilterInitialized = false

	testLblsA = map[string]string{"key-a": "val-1"}
	testLblsB = map[string]string{"key-b": "val-2"}
	testLblsC = map[string]string{"key-c": "val-3"}
)

type testQueueOps struct {
	fakeWorkQueue map[string]bool
}

func (t testQueueOps) enqueueCIDReconciliation(cidKey resource.Key) {
	t.fakeWorkQueue[cidKey.String()] = true
}

func (t testQueueOps) enqueuePodReconciliation(cidKey resource.Key) {
	t.fakeWorkQueue[cidKey.String()] = true
}

func testNewReconciler(ctx context.Context, enableCES bool) (*reconciler, *testQueueOps, k8sClient.FakeClientset, func()) {
	var namespace resource.Resource[*slim_corev1.Namespace]
	var pod resource.Resource[*slim_corev1.Pod]
	var ciliumIdentity resource.Resource[*capi_v2.CiliumIdentity]
	var ciliumEndpointSlice resource.Resource[*capi_v2a1.CiliumEndpointSlice]
	var fakeClient k8sClient.FakeClientset

	hive := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		cell.Metric(NewMetrics),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			nsResource resource.Resource[*slim_corev1.Namespace],
			podResource resource.Resource[*slim_corev1.Pod],
			cidResource resource.Resource[*capi_v2.CiliumIdentity],
			cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice],
		) error {
			fakeClient = *c
			namespace = nsResource
			pod = podResource
			ciliumIdentity = cidResource
			ciliumEndpointSlice = cesResource
			return nil
		}),
	)
	hive.Start(ctx)
	cleanupFunc := func() {
		hive.Stop(ctx)
	}

	queueOps := &testQueueOps{fakeWorkQueue: make(map[string]bool)}
	reconciler := newReconciler(
		ctx,
		log,
		fakeClient.Clientset,
		namespace,
		pod,
		ciliumIdentity,
		ciliumEndpointSlice,
		enableCES,
		queueOps,
	)
	return reconciler, queueOps, fakeClient, cleanupFunc
}

func testCreateCIDObj(id string, lbls map[string]string) *capi_v2.CiliumIdentity {
	secLbls := make(map[string]string)
	for k, v := range lbls {
		secLbls[k] = v
	}

	k := GetCIDKeyFromK8sLabels(secLbls)
	secLbls = k.GetAsMap()
	selectedLabels, _ := idbackend.SanitizeK8sLabels(secLbls)

	return &capi_v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   id,
			Labels: selectedLabels,
		},
		SecurityLabels: secLbls,
	}
}

func testCreatePodObj(name, namespace string, lbls, annotations map[string]string) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      lbls,
			Annotations: annotations,
		},
	}
}

func testCreateNSObj(name string, lbls map[string]string) *slim_corev1.Namespace {
	if lbls == nil {
		lbls = make(map[string]string)
	}

	lbls["kubernetes.io/metadata.name"] = name

	return &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:   name,
			Labels: lbls,
		},
	}
}

func testIDMatches(t *testing.T, r *reconciler, id string, lbls map[string]string, assertTxt string) {
	k, exists := r.desiredCIDState.LookupByID(id)
	assert.Equal(t, true, exists, assertTxt)
	expectedLbls := GetCIDKeyFromK8sLabels(lbls).GetAsMap()
	gotLbls := k.GetAsMap()
	for lblKey, lblVal := range expectedLbls {
		assert.Equal(t, lblVal, gotLbls[lblKey], assertTxt)
	}
}

func testInitLabelsFilter() {
	if testLabelsFilterInitialized {
		return
	}

	labelsfilter.ParseLabelPrefixCfg(nil, nil, "")
	testLabelsFilterInitialized = true
}

func testVerifyCIDUsageInPods(t *testing.T, usage *CIDUsageInPods, expectedCIDs, expectedPods int, assertTxt string) {
	assert.Equal(t, expectedCIDs, len(usage.cidUsageCount), assertTxt)
	assert.Equal(t, expectedPods, len(usage.podToCID), assertTxt)

	totalUsedCIDs := 0
	for _, count := range usage.cidUsageCount {
		totalUsedCIDs += count
	}

	assert.Equal(t, expectedPods, totalUsedCIDs, assertTxt)
}

func TestSyncCESsOnStartup(t *testing.T) {
	ctx := context.Background()
	reconciler, _, _, cleanupFunc := testNewReconciler(ctx, false)
	defer cleanupFunc()

	cep1 := cestest.CreateManagerEndpoint("cep1", 1000)
	cep2 := cestest.CreateManagerEndpoint("cep2", 1000)
	cep3 := cestest.CreateManagerEndpoint("cep3", 2000)
	cep4 := cestest.CreateManagerEndpoint("cep4", 2000)
	ces1 := cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1, cep2, cep3, cep4})
	reconciler.cesStore.CacheStore().Add(ces1)
	cep5 := cestest.CreateManagerEndpoint("cep5", 1000)
	cep6 := cestest.CreateManagerEndpoint("cep6", 1000)
	cep7 := cestest.CreateManagerEndpoint("cep7", 2000)
	ces2 := cestest.CreateStoreEndpointSlice("ces2", "ns", []capi_v2a1.CoreCiliumEndpoint{cep5, cep6, cep7})
	reconciler.cesStore.CacheStore().Add(ces2)

	reconciler.syncCESsOnStartup()
	assert.Equal(t, 0, len(reconciler.cidUsageInCES.cidUsageCount), "No CIDs are used in CESs when CES is disabled")

	reconciler.cesEnabled = true

	reconciler.syncCESsOnStartup()
	assert.Equal(t, 2, len(reconciler.cidUsageInCES.cidUsageCount), "There are 2 different CIDs used in CESs")

	cidsUsed := reconciler.cidUsageInCES.cidUsageCount[1000]
	assert.Equal(t, 4, cidsUsed, "There are 4 endpoints in CESs that use CID 1000")

	cidsUsed = reconciler.cidUsageInCES.cidUsageCount[2000]
	assert.Equal(t, 3, cidsUsed, "There are 3 endpoints in CESs that use CID 2000")
}

func TestSyncPodsOnStartup(t *testing.T) {
	testInitLabelsFilter()
	ctx := context.Background()
	reconciler, queueOps, _, cleanupFunc := testNewReconciler(ctx, false)
	defer cleanupFunc()

	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns1", nil))
	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns2", nil))

	pod1 := testCreatePodObj("pod1", "ns1", testLblsA, nil)
	pod2 := testCreatePodObj("pod2", "ns2", testLblsA, nil)
	pod3 := testCreatePodObj("pod3", "ns1", testLblsB, nil)
	pod4 := testCreatePodObj("pod4", "ns1", testLblsB, nil)
	pod5 := testCreatePodObj("pod5", "ns1", testLblsC, nil)
	reconciler.podStore.CacheStore().Add(pod1)
	reconciler.podStore.CacheStore().Add(pod2)
	reconciler.podStore.CacheStore().Add(pod3)
	reconciler.podStore.CacheStore().Add(pod4)
	reconciler.podStore.CacheStore().Add(pod5)

	reconciler.syncPodsOnStartup()
	assert.Equal(t, 4, len(queueOps.fakeWorkQueue), "CID queue contains 4 enqueued events for 4 new CIDs")

	lbls1, _ := reconciler.getRelevantLabelsForPod(pod1)
	lbls2, _ := reconciler.getRelevantLabelsForPod(pod2)
	lbls3, _ := reconciler.getRelevantLabelsForPod(pod3)

	cidLabels1 := GetCIDKeyFromK8sLabels(lbls1)
	cidLabels2 := GetCIDKeyFromK8sLabels(lbls2)
	cidLabels3 := GetCIDKeyFromK8sLabels(lbls3)

	log.Info(cidLabels1.GetAsMap())

	cid1 := testCreateCIDObj("1000", cidLabels1.GetAsMap())
	cid2 := testCreateCIDObj("2000", cidLabels2.GetAsMap())
	cid3 := testCreateCIDObj("3000", cidLabels3.GetAsMap())
	reconciler.cidStore.CacheStore().Add(cid1)
	reconciler.cidStore.CacheStore().Add(cid2)
	reconciler.cidStore.CacheStore().Add(cid3)

	reconciler.syncPodsOnStartup()
	assert.Equal(t, 4, len(queueOps.fakeWorkQueue), "CID queue contains 4 enqueued event, 1 more for 1 new CID")
}

func TestReconcileCID(t *testing.T) {
	testInitLabelsFilter()

	ctx := context.Background()
	reconciler, _, _, cleanupFunc := testNewReconciler(ctx, false)
	defer cleanupFunc()

	clientset := reconciler.clientset.(*k8sClient.FakeClientset)

	var nilCID *capi_v2.CiliumIdentity
	var createCID, updateCID *capi_v2.CiliumIdentity
	var deleteCIDName string
	clientset.CiliumFakeClientset.PrependReactor("create", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.CreateAction)
		createCID = pa.GetObject().(*capi_v2.CiliumIdentity)
		return true, nil, nil
	})
	clientset.CiliumFakeClientset.PrependReactor("update", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.UpdateAction)
		updateCID = pa.GetObject().(*capi_v2.CiliumIdentity)
		return true, nil, nil
	})
	clientset.CiliumFakeClientset.PrependReactor("delete", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		pa := action.(k8sTesting.DeleteAction)
		deleteCIDName = pa.GetName()
		return true, nil, nil
	})

	cidName := "1000"
	cid := testCreateCIDObj(cidName, testLblsA)
	assert.NoError(t, reconciler.reconcileCID(cidResourceKey(cidName)))
	assert.Equal(t, nilCID, createCID, "CID is not created when it doesn't exist in the watcher store or the desired state")
	assert.Equal(t, nilCID, updateCID, "CID is not updated when it doesn't exist in the watcher store or the desired state")
	assert.Equal(t, "", deleteCIDName, "CID is not deleted when it doesn't exist in the watcher store or the desired state")

	assert.NoError(t, reconciler.upsertDesiredState(cidName, GetCIDKeyFromK8sLabels(testLblsA)))

	reconciler.cidUsageInPods.cidUsageCount[cidName] = 1
	assert.NoError(t, reconciler.reconcileCID(cidResourceKey(cidName)))
	assert.Equal(t, cid, createCID, "CID is created when it exists in the desired state but not in the watcher store")
	assert.Equal(t, nilCID, updateCID, "CID is created when it exists in the desired state but not in the watcher store")
	assert.Equal(t, "", deleteCIDName, "CID is created when it exists in the desired state but not in the watcher store")
	createCID = nil

	reconciler.cidStore.CacheStore().Add(cid)
	assert.NoError(t, reconciler.reconcileCID(cidResourceKey(cidName)))
	assert.Equal(t, nilCID, createCID, "CID is not created when it exists both in the desired state and in the watcher store")
	assert.Equal(t, nilCID, updateCID, "CID is not updated when it exists both in the desired state and in the watcher store")
	assert.Equal(t, "", deleteCIDName, "CID is not deleted when it exists both in the desired state and in the watcher store")

	reconciler.desiredCIDState.Remove(cidName)
	cidNum, err := strconv.Atoi(cidName)
	assert.NoError(t, err)
	reconciler.idAllocator.ReturnToAvailablePool(idpool.ID(cidNum))

	assert.NoError(t, reconciler.reconcileCID(cidResourceKey(cidName)))
	assert.Equal(t, nilCID, createCID, "CID is not created when it exists in the watcher store but not in the desired state")
	assert.Equal(t, nilCID, updateCID, "CID is not updated when it exists in the watcher store but not in the desired state")
	assert.Equal(t, cidName, deleteCIDName, "CID is deleted when it exists in the watcher store but not in the desired state")
	deleteCIDName = ""

	cidv2 := testCreateCIDObj(cidName, testLblsB)
	reconciler.cidStore.CacheStore().Update(cidv2)

	assert.NoError(t, reconciler.upsertDesiredState(cidName, GetCIDKeyFromK8sLabels(testLblsA)))
	assert.NoError(t, reconciler.reconcileCID(cidResourceKey(cidName)))
	assert.Equal(t, nilCID, createCID, "CID is not created when labels don't match between the desired state and the watcher store")
	assert.Equal(t, cidv2, updateCID, "CID is updated when labels don't match between the desired state and the watcher store")
	assert.Equal(t, "", deleteCIDName, "CID is not deleted when labels don't match between the desired state and the watcher store")
}

func TestReconcilePod(t *testing.T) {
	testInitLabelsFilter()
	ctx := context.Background()
	reconciler, queueOps, _, cleanupFunc := testNewReconciler(ctx, false)
	defer cleanupFunc()

	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns1", nil))
	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns2", nil))

	assertTxt := "Pod doesn't exist in the watcher store and isn't used in the pod to CID mapping. No CID reconciliation"
	err := reconciler.reconcilePod(podResourceKey("pod1", "ns1"))
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 0, len(queueOps.fakeWorkQueue), assertTxt)
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 0, 0, "0 Pods and CIDs are expected")

	assertTxt = "Pod doesn't exist in the watcher store, but it's used in the pod to CID mapping. CID will be enqueued for reconciliation because of CID clean up"
	cidName2 := "2000"
	podKey2 := podResourceKey("pod2", "ns1")
	reconciler.cidUsageInPods.AssignCIDToPod(podKey2.String(), cidName2)
	err = reconciler.reconcilePod(podKey2)
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 1, len(queueOps.fakeWorkQueue), assertTxt)
	assert.Equal(t, true, queueOps.fakeWorkQueue[cidName2], assertTxt)
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 0, 0, "0 Pods and CIDs are expected")

	assertTxt = "Pod exists in the watcher store, no CID exists for it, and it isn't used in the pod to CID mapping. CID will be enqueued for reconciliation because new CID needs to be created"
	queueOps.fakeWorkQueue = make(map[string]bool)
	pod3 := testCreatePodObj("pod3", "ns1", testLblsB, nil)
	reconciler.podStore.CacheStore().Add(pod3)
	err = reconciler.reconcilePod(podResourceKey("pod3", "ns1"))
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 1, len(queueOps.fakeWorkQueue), assertTxt)
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 1, 1, "1 Pods and CIDs are expected")

	var enqueuedID string
	for id := range queueOps.fakeWorkQueue {
		enqueuedID = id
	}
	testIDMatches(t, reconciler, enqueuedID, testLblsB, assertTxt)

	queueOps.fakeWorkQueue = make(map[string]bool)
	cidName4 := "4000"
	pod4 := testCreatePodObj("pod4", "ns1", testLblsC, nil)
	reconciler.podStore.CacheStore().Add(pod4)
	podKey4 := podResourceKey("pod4", "ns1")
	reconciler.cidUsageInPods.AssignCIDToPod(podKey4.String(), cidName4)

	err = reconciler.reconcilePod(podResourceKey("pod4", "ns1"))
	assertTxt = "Pod exists in the watcher store, no CID exists for it, but it exists in the pod to CID mapping. CID will be enqueued for reconciliation both because new CID needs to be created and old CID needs to be cleaned up"
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 2, len(queueOps.fakeWorkQueue), assertTxt)
	for id := range queueOps.fakeWorkQueue {
		if id == cidName4 {
			continue
		}
		testIDMatches(t, reconciler, id, testLblsC, assertTxt)
	}
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 2, 2, "2 Pods and 2 CID expected")

	assertTxt = "Pod exists in the watcher store, CID exists for it, but it isn't used in the pod to CID mapping. No CID reconciliation"
	queueOps.fakeWorkQueue = make(map[string]bool)
	cidName5 := "5000"
	cid5 := testCreateCIDObj(cidName5, testLblsA)
	reconciler.cidStore.CacheStore().Add(cid5)
	pod5 := testCreatePodObj("pod5", "ns1", testLblsC, nil)
	reconciler.podStore.CacheStore().Add(pod5)
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 2, 2, "2 Pods and 2 CID expected")

	err = reconciler.reconcilePod(podResourceKey("pod5", "ns1"))
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 0, len(queueOps.fakeWorkQueue), assertTxt)

	assertTxt = "Pod exists in the watcher store, CID exists for it, and it exists in the pod to CID mapping. CID will be enqueued for reconciliation because of CID clean up"
	podKey5 := podResourceKey("pod5", "ns1")
	reconciler.cidUsageInPods.AssignCIDToPod(podKey5.String(), cidName5)
	err = reconciler.reconcilePod(podResourceKey("pod5", "ns1"))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(queueOps.fakeWorkQueue), assertTxt)
	assert.Equal(t, true, queueOps.fakeWorkQueue[cidName5], assertTxt)
	testVerifyCIDUsageInPods(t, reconciler.cidUsageInPods, 2, 3, "3 Pods and 2 CID expected")
}

func TestReconcileNS(t *testing.T) {
	testInitLabelsFilter()
	ctx := context.Background()
	reconciler, queueOps, _, cleanupFunc := testNewReconciler(ctx, false)
	defer cleanupFunc()

	assertTxt := "No pods are enqueued to be reconciled when there are no pods in the watcher store"
	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns1", nil))
	err := reconciler.reconcileNS(nsResourceKey("ns1"))
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 0, len(queueOps.fakeWorkQueue), assertTxt)

	pod1 := testCreatePodObj("pod1", "ns1", testLblsA, nil)
	pod2 := testCreatePodObj("pod2", "ns1", testLblsA, nil)
	pod3 := testCreatePodObj("pod3", "ns1", testLblsB, nil)
	pod4 := testCreatePodObj("pod4", "ns1", testLblsB, nil)
	pod5 := testCreatePodObj("pod5", "ns1", testLblsC, nil)
	reconciler.podStore.CacheStore().Add(pod1)
	reconciler.podStore.CacheStore().Add(pod2)
	reconciler.podStore.CacheStore().Add(pod3)
	reconciler.podStore.CacheStore().Add(pod4)
	reconciler.podStore.CacheStore().Add(pod5)

	assertTxt = "No pods are enqueued to be reconciled when there are no pods in the watcher store for this namespace"
	reconciler.nsStore.CacheStore().Add(testCreateNSObj("ns2", nil))
	err = reconciler.reconcileNS(nsResourceKey("ns2"))
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 0, len(queueOps.fakeWorkQueue), assertTxt)

	assertTxt = "All 5 pods in the namespace are enqueued to be reconciled"
	err = reconciler.reconcileNS(nsResourceKey("ns1"))
	assert.NoError(t, err, assertTxt)
	assert.Equal(t, 5, len(queueOps.fakeWorkQueue), assertTxt)
}
