// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/google/go-cmp/cmp"
	prometheustestutil "github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	cestest "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	WaitUntilTimeout = 5 * time.Second
)

func TestRegisterControllerWithOperatorManagingCIDs(t *testing.T) {
	cidResource, cesResource, fakeClient, m, h := initHiveTest(true)

	ctx := context.Background()
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}

	if err := createNsAndPod(ctx, fakeClient); err != nil {
		t.Errorf("Failed to create namespace or pod: %v", err)
	}

	cidStore, _ := (*cidResource).Store(ctx)
	err := testutils.WaitUntil(func() bool { return len(cidStore.List()) > 0 }, WaitUntilTimeout)
	if err != nil {
		t.Errorf("Expected CID to be created, got %v", err)
	}

	if err := verifyCIDUsageInCES(ctx, fakeClient, *cidResource, *cesResource); err != nil {
		t.Errorf("Failed to verify CID usage in CES, got %v", err)
	}

	if count := prometheustestutil.CollectAndCount(m.EventCount); count < 1 {
		t.Errorf("Expected at least one element in EventCount, but got %d", count)
	}

	if count := prometheustestutil.CollectAndCount(m.QueueLatency); count < 1 {
		t.Errorf("Expected at least one element in QueueLatency, but got %d", count)
	}

	if err := h.Stop(tlog, ctx); err != nil {
		t.Fatalf("stopping hive encountered an error: %v", err)
	}
}

func TestRegisterController(t *testing.T) {
	cidResource, _, fakeClient, m, h := initHiveTest(false)

	ctx := context.Background()
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}

	if err := createNsAndPod(ctx, fakeClient); err != nil {
		t.Errorf("Failed to create namespace or pod: %v", err)
	}

	cidStore, _ := (*cidResource).Store(ctx)
	if len(cidStore.List()) != 0 {
		t.Errorf("Expected no CIDs to be present in the store, but found %d", len(cidStore.List()))
	}

	if count := prometheustestutil.CollectAndCount(m.EventCount); count != 0 {
		t.Errorf("Expected no elements in EventCount, but found %d", count)
	}

	if count := prometheustestutil.CollectAndCount(m.QueueLatency); count != 0 {
		t.Errorf("Expected no elements in QueueLatency, but found %d", count)
	}

	if err := h.Stop(tlog, ctx); err != nil {
		t.Fatalf("stopping hive encountered an error: %v", err)
	}
}

func initHiveTest(operatorManagingCID bool) (*resource.Resource[*capi_v2.CiliumIdentity], *resource.Resource[*capi_v2a1.CiliumEndpointSlice], *k8sClient.FakeClientset, *Metrics, *hive.Hive) {
	var cidResource resource.Resource[*capi_v2.CiliumIdentity]
	var cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]
	var fakeClient k8sClient.FakeClientset
	var cidMetrics Metrics

	h := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Provide(func() config {
			return config{
				EnableOperatorManageCIDs: operatorManagingCID,
			}
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: true,
			}
		}),
		cell.Provide(func(lc cell.Lifecycle, p types.Provider, jr job.Registry) job.Group {
			h := p.ForModule(cell.FullModuleID{"test"})
			jg := jr.NewGroup(h)
			lc.Append(jg)
			return jg
		}),
		cell.Invoke(func(p params) error {
			registerController(p)
			return nil
		}),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cid resource.Resource[*capi_v2.CiliumIdentity],
			ces resource.Resource[*capi_v2a1.CiliumEndpointSlice],
			m *Metrics,
		) error {
			fakeClient = *c
			cidResource = cid
			cesResource = ces
			cidMetrics = *m
			return nil
		}),
	)
	return &cidResource, &cesResource, &fakeClient, &cidMetrics, h
}

func createNsAndPod(ctx context.Context, fakeClient *k8sClient.FakeClientset) error {
	ns := testCreateNSObj("ns1", nil)
	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		return err
	}
	pod := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	if _, err := fakeClient.Slim().CoreV1().Pods("ns1").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func verifyCIDUsageInCES(ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]) error {
	cidStore, _ := cidResource.Store(ctx)
	cids := cidStore.List()
	if len(cids) == 0 {
		return fmt.Errorf("no CIDs found in the store")
	}

	cidNum, err := strconv.Atoi(cids[0].Name)
	if err != nil {
		return err
	}

	cep1 := cestest.CreateManagerEndpoint("cep1", int64(cidNum))
	ces1 := cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1})
	if _, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(ctx, ces1, metav1.CreateOptions{}); err != nil {
		return err
	}

	cesStore, _ := cesResource.Store(context.Background())
	if err := testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, WaitUntilTimeout); err != nil {
		return fmt.Errorf("failed to get CES: %w", err)
	}

	// CID is not deleted even when Pod is, because the CID is still used in CES.
	if err := fakeClient.Slim().CoreV1().Pods("ns1").Delete(ctx, "pod1", metav1.DeleteOptions{}); err != nil {
		return err
	}

	if len(cidStore.List()) == 0 {
		return fmt.Errorf("expected for CID to not be deleted")
	}

	if err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Delete(ctx, ces1.Name, metav1.DeleteOptions{}); err != nil {
		return err
	}

	return nil
}

func TestCreateTwoPodsWithSameLabels(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)

	pod1 := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	pod2 := testCreatePodObj("pod2", "ns1", testLbsA, nil)
	pod3 := testCreatePodObj("pod3", "ns1", testLbsB, nil)

	cid1 := testCreateCIDObjNs("1000", pod1, ns1)
	cid2 := testCreateCIDObjNs("2000", pod3, ns1)

	// Start test hive.
	cidResource, _, fakeClient, _, h := initHiveTest(true)
	ctx, cancelCtxFunc := context.WithCancel(context.Background())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Start listening to identities events but discard all events being replayed.
	events := (*cidResource).Events(ctx)
	for ev := range events {
		ev.Done(nil)
		if ev.Kind == resource.Sync {
			break
		}
	}

	// Create the first pod.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Wait for update event to propagate.
	ev := <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid1.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid1.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)

	// Create the second pod with the same labels.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod2.Namespace).Create(ctx, pod2, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Create the third pod with different labels.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod3.Namespace).Create(ctx, pod3, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Wait for reconciler to create a new CID based on pod3.
	// This also confirms that pod2 creation didn't trigger creation of a new CID.
	ev = <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid2.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid2.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)
}

func TestUpdatePodLabels(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)

	pod1 := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	pod1b := testCreatePodObj("pod1", "ns1", testLbsB, nil)

	cid1 := testCreateCIDObjNs("1000", pod1, ns1)
	cid2 := testCreateCIDObjNs("2000", pod1b, ns1)

	// Start test hive.
	cidResource, _, fakeClient, _, h := initHiveTest(true)
	ctx, cancelCtxFunc := context.WithCancel(context.Background())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Start listening to identities events but discard all events being replayed.
	events := (*cidResource).Events(ctx)
	for ev := range events {
		ev.Done(nil)
		if ev.Kind == resource.Sync {
			break
		}
	}

	// Create the first pod.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Wait for update event to propagate.
	ev := <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid1.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid1.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)

	// Update labels of the first pod.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod1b.Namespace).Update(ctx, pod1b, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update pod: %v", err)
	}

	// Wait for reconciler to create a new CID based on the updated pod.
	ev = <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid2.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid2.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)
}

func TestUpdateUsedCIDIsReverted(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)

	pod1 := testCreatePodObj("pod1", "ns1", testLbsC, nil)
	pod2 := testCreatePodObj("pod2", "ns1", testLbsB, nil)

	cid1 := testCreateCIDObjNs("1000", pod1, ns1)
	cid2 := testCreateCIDObjNs("2000", pod2, ns1)

	// Start test hive.
	cidResource, _, fakeClient, _, h := initHiveTest(true)
	ctx, cancelCtxFunc := context.WithCancel(context.Background())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Check initial status of CiliumIdentity resource after pods creation.
	store, err := (*cidResource).Store(ctx)
	if err != nil {
		t.Fatalf("unexpected error while getting CID store: %s", err)
	}

	var (
		lastErr  error
		toUpdate *capi_v2.CiliumIdentity
	)
	if err := testutils.WaitUntil(func() bool {
		cids := store.List()
		if len(cids) != 1 {
			lastErr = fmt.Errorf("expected 1 identity, got %d", len(cids))
			return false
		}
		toUpdate = cids[0]
		return true
	}, WaitUntilTimeout); err != nil {
		t.Fatalf("timeout waiting for identities in store: %s", lastErr)
	}

	// Start listening to identities events but discard all events being replayed.
	events := (*cidResource).Events(ctx)
	for ev := range events {
		ev.Done(nil)
		if ev.Kind == resource.Sync {
			break
		}
	}

	// Update identity.
	updated := toUpdate.DeepCopy()
	updated.Labels = cid2.Labels
	updated.SecurityLabels = cid2.SecurityLabels
	if _, err := fakeClient.CiliumV2().CiliumIdentities().Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update CID: %v", err)
	}

	// Wait for update event to propagate.
	ev := <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if ev.Key.Name != toUpdate.Name {
		t.Fatalf("expected upsert event for cid %s, got %v", toUpdate.Name, ev.Key.Name)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, updated.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", updated.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)

	// Wait for reconciler to revert the change.
	ev = <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if ev.Key.Name != toUpdate.Name {
		t.Fatalf("expected upsert event for cid %s, got %v", toUpdate.Name, ev.Key.Name)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid1.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid1.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)
}

func TestDeleteUsedCIDIsRecreated(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)
	pod1 := testCreatePodObj("pod1", "ns1", testLbsC, nil)
	cid1 := testCreateCIDObjNs("1000", pod1, ns1)

	// Start test hive.
	cidResource, _, fakeClient, _, h := initHiveTest(true)
	ctx, cancelCtxFunc := context.WithCancel(context.Background())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Check initial status of CiliumIdentity resource after pods creation.
	store, err := (*cidResource).Store(ctx)
	if err != nil {
		t.Fatalf("unexpected error while getting CID store: %s", err)
	}

	var (
		lastErr  error
		toDelete *capi_v2.CiliumIdentity
	)
	if err := testutils.WaitUntil(func() bool {
		cids := store.List()
		if len(cids) != 1 {
			lastErr = fmt.Errorf("expected 1 identity, got %d", len(cids))
			return false
		}
		toDelete = cids[0]
		return true
	}, WaitUntilTimeout); err != nil {
		t.Fatalf("timeout waiting for identities in store: %s", lastErr)
	}

	// Start listening to identities events but discard all events being replayed.
	events := (*cidResource).Events(ctx)
	for ev := range events {
		ev.Done(nil)
		if ev.Kind == resource.Sync {
			break
		}
	}

	// Update identity.
	if err := fakeClient.CiliumV2().CiliumIdentities().Delete(ctx, toDelete.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete CID: %v", err)
	}

	// Wait for delete event to propagate.
	ev := <-events
	if ev.Kind != resource.Delete {
		t.Fatalf("expected delete event, got %v", ev.Kind)
	}
	if ev.Key.Name != toDelete.Name {
		t.Fatalf("expected delete event for cid %s, got %v", toDelete.Name, ev.Key.Name)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, toDelete.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", toDelete.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)

	// Wait for reconciler to recreate the CID.
	ev = <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if ev.Key.Name != toDelete.Name {
		t.Fatalf("expected upsert event for cid %s, got %v", toDelete.Name, ev.Key.Name)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid1.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid1.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)
}
