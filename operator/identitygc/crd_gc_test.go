// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/auth/spire"
	"github.com/cilium/cilium/operator/k8s"
	tu "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestUsedIdentitiesInCESs(t *testing.T) {
	var fakeClient *k8sClient.FakeClientset
	var ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Invoke(func(c *k8sClient.FakeClientset, ces resource.Resource[*cilium_v2a1.CiliumEndpointSlice]) error {
			fakeClient = c
			ciliumEndpointSlice = ces
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	err := hive.Start(tlog, t.Context())
	if err != nil {
		t.Fatalf("unable to start hive for the test: %s", err)
	}

	cesStore, _ := ciliumEndpointSlice.Store(t.Context())

	// Empty store.
	gotIdentities := usedIdentitiesInCESs(cesStore)
	wantIdentities := make(map[string]bool)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 5 IDs in the store.
	cesA := tu.CreateCESWithIDs("cesA", []int64{1, 2, 3, 4, 5})
	fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), cesA, meta_v1.CreateOptions{})
	err = testutils.WaitUntil(isCESPresent("cesA", cesStore), time.Second)
	if err != nil {
		t.Fatalf("cesA not present in the store after timeout: %s", err)
	}
	wantIdentities["1"] = true
	wantIdentities["2"] = true
	wantIdentities["3"] = true
	wantIdentities["4"] = true
	wantIdentities["5"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	// 10 IDs in the store.
	cesB := tu.CreateCESWithIDs("cesB", []int64{10, 20, 30, 40, 50})
	fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(t.Context(), cesB, meta_v1.CreateOptions{})
	err = testutils.WaitUntil(isCESPresent("cesB", cesStore), time.Second)
	if err != nil {
		t.Fatalf("cesB not present in the store after timeout: %s", err)
	}
	wantIdentities["10"] = true
	wantIdentities["20"] = true
	wantIdentities["30"] = true
	wantIdentities["40"] = true
	wantIdentities["50"] = true
	gotIdentities = usedIdentitiesInCESs(cesStore)
	assertEqualIDs(t, wantIdentities, gotIdentities)

	err = hive.Stop(tlog, t.Context())
	if err != nil {
		t.Fatalf("unable to stop hive for the test: %s", err)
	}
}

func isCESPresent(cesName string, cesStore resource.Store[*cilium_v2a1.CiliumEndpointSlice]) testutils.ConditionFunc {
	return func() bool {
		_, exists, _ := cesStore.GetByKey(resource.Key{Name: cesName})
		return exists
	}
}

func assertEqualIDs(t *testing.T, wantIdentities, gotIdentities map[string]bool) {
	t.Helper()
	if diff := cmp.Diff(wantIdentities, gotIdentities); diff != "" {
		t.Errorf("Unexpected Identites in the CES store (-want +got): \n%s", diff)
	}
}

// TestHeartbeatUpdater verifies that an unused identity is marked and then
// deleted by consecutive GC passes, without unnecessarily deferring the
// deletion by another heartbeat period. An identity with an endpoint must
// survive.
func TestHeartbeatUpdater(t *testing.T) {
	const (
		unused = "88888"
		inUse  = "99999"
	)

	var (
		fakeClient  *k8sClient.FakeClientset
		identityRes resource.Resource[*cilium_v2.CiliumIdentity]
		cepRes      resource.Resource[*cilium_v2.CiliumEndpoint]
	)
	h := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Invoke(func(c *k8sClient.FakeClientset, id resource.Resource[*cilium_v2.CiliumIdentity], cep resource.Resource[*cilium_v2.CiliumEndpoint]) error {
			fakeClient, identityRes, cepRes = c, id, cep
			if err := setupCiliumIdentities(t, c); err != nil {
				return err
			}
			return setupCiliumEndpoint(t, c)
		}),
	)

	ctx := t.Context()
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	t.Cleanup(func() {
		// t.Context() is cancelled before cleanup runs, so use a fresh
		// context to stop the hive.
		if err := h.Stop(tlog, context.Background()); err != nil {
			t.Fatalf("failed to stop: %s", err)
		}
	})

	// Store waits for the initial listing, so both identities are present.
	idStore, err := identityRes.Store(ctx)
	require.NoError(t, err)

	identity := &identityEvents{
		Resource: identityRes,
		events:   make(chan resource.Event[*cilium_v2.CiliumIdentity]),
	}
	igc := &GC{
		logger:             tlog,
		clientset:          fakeClient.CiliumV2().CiliumIdentities(),
		identity:           identity,
		ciliumEndpoint:     cepRes,
		authIdentityClient: spire.NewFakeClient(),
		heartbeatStore:     newHeartbeatStore(time.Hour, tlog),
		rateLimiter:        rate.NewLimiter(time.Minute, 100),
		metrics:            NewMetrics(),
	}
	t.Cleanup(igc.rateLimiter.Stop)
	// Pretend the operator has been running longer than the heartbeat timeout
	// so the startup grace period does not keep identities alive.
	igc.heartbeatStore.firstRun = time.Now().Add(-2 * time.Hour)

	updaterDone := make(chan struct{})
	go func() {
		defer close(updaterDone)
		_ = igc.runHeartbeatUpdater(ctx)
	}()

	getIdentity := func(name string) (*cilium_v2.CiliumIdentity, error) {
		return fakeClient.CiliumV2().CiliumIdentities().Get(ctx, name, meta_v1.GetOptions{})
	}

	// First pass marks the unused identity for deletion and leaves the in-use
	// one alone.
	require.NoError(t, igc.gc(ctx))
	marked, err := getIdentity(unused)
	require.NoError(t, err)
	require.Contains(t, marked.Annotations, identitybackend.HeartBeatAnnotation)
	_, err = getIdentity(inUse)
	require.NoError(t, err)

	// The mark-for-deletion write comes back through the informer as an
	// Upsert. It must not keep the identity alive.
	identity.feed(t, resource.Upsert, marked)

	// Wait for the store to observe the annotation so the next pass evaluates
	// the identity for deletion.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		obj, exists, err := idStore.GetByKey(resource.Key{Name: unused})
		if assert.NoError(c, err) && assert.True(c, exists) {
			assert.Contains(c, obj.Annotations, identitybackend.HeartBeatAnnotation)
		}
	}, time.Second, 10*time.Millisecond)

	// Second pass deletes the unused identity and the in-use one survives.
	require.NoError(t, igc.gc(ctx))
	_, err = getIdentity(unused)
	require.True(t, k8serrors.IsNotFound(err), "unused identity should be deleted, got %v", err)
	_, err = getIdentity(inUse)
	require.NoError(t, err)

	close(identity.events)
	select {
	case <-updaterDone:
	case <-time.After(10 * time.Second):
		t.Fatal("runHeartbeatUpdater did not exit")
	}
}

type identityEvents struct {
	resource.Resource[*cilium_v2.CiliumIdentity]
	events chan resource.Event[*cilium_v2.CiliumIdentity]
}

func (r *identityEvents) Events(context.Context, ...resource.EventsOpt) <-chan resource.Event[*cilium_v2.CiliumIdentity] {
	return r.events
}

// feed delivers an event to runHeartbeatUpdater and blocks until it has been
// processed.
func (r *identityEvents) feed(t *testing.T, kind resource.EventKind, obj *cilium_v2.CiliumIdentity) {
	t.Helper()
	done := make(chan error)
	r.events <- resource.Event[*cilium_v2.CiliumIdentity]{
		Kind:   kind,
		Object: obj,
		Done:   func(err error) { done <- err },
	}
	require.NoError(t, <-done)
}
