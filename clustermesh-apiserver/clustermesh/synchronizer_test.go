// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

// fakeCEPStore is a minimal resource.Store backed by a map, implementing
// only the methods leveraged by the synchronizer.
type fakeCEPStore struct {
	resource.Store[*types.CiliumEndpoint]
	objects map[resource.Key]*types.CiliumEndpoint
}

func newFakeCEPStore() *fakeCEPStore {
	return &fakeCEPStore{objects: make(map[resource.Key]*types.CiliumEndpoint)}
}

func (f *fakeCEPStore) add(cep *types.CiliumEndpoint) { f.objects[resource.NewKey(cep)] = cep }

func (f *fakeCEPStore) remove(cep *types.CiliumEndpoint) { delete(f.objects, resource.NewKey(cep)) }

func (f *fakeCEPStore) GetByKey(key resource.Key) (*types.CiliumEndpoint, bool, error) {
	obj, ok := f.objects[key]
	return obj, ok, nil
}

func (f *fakeCEPStore) ByIndex(indexName, indexedValue string) ([]*types.CiliumEndpoint, error) {
	if indexName != cache.NamespaceIndex {
		return nil, fmt.Errorf("index %q not found", indexName)
	}

	var out []*types.CiliumEndpoint
	for key, obj := range f.objects {
		if key.Namespace == indexedValue {
			out = append(out, obj)
		}
	}
	return out, nil
}

// fakeSyncStore records the current content of the kvstore, as resulting from
// the upsert and delete operations issued by the synchronizer.
type fakeSyncStore struct {
	store.SyncStore
	kvs map[string]string
}

func newFakeSyncStore() *fakeSyncStore {
	return &fakeSyncStore{kvs: make(map[string]string)}
}

func (f *fakeSyncStore) UpsertKey(_ context.Context, key store.Key) error {
	value, err := key.Marshal()
	if err != nil {
		return err
	}
	f.kvs[key.GetKeyName()] = string(value)
	return nil
}

func (f *fakeSyncStore) DeleteKey(_ context.Context, key store.NamedKey) error {
	delete(f.kvs, key.GetKeyName())
	return nil
}

// owner returns the namespace/name of the CiliumEndpoint currently associated
// with the given IP in the kvstore, if any.
func (f *fakeSyncStore) owner(t *testing.T, ip string) (string, bool) {
	t.Helper()

	value, ok := f.kvs[ip]
	if !ok {
		return "", false
	}

	var pair identity.IPIdentityPair
	require.NoError(t, json.Unmarshal([]byte(value), &pair))
	return pair.K8sNamespace + "/" + pair.K8sPodName, true
}

// fakeNamespaceManager treats all namespaces as global, unless listed in nonGlobal.
type fakeNamespaceManager struct {
	nonGlobal map[string]bool
	err       error
}

func (f *fakeNamespaceManager) IsGlobalNamespaceByName(ns string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return !f.nonGlobal[ns], nil
}

func (f *fakeNamespaceManager) IsGlobalNamespaceByObject(ns *slim_corev1.Namespace) bool {
	return !f.nonGlobal[ns.Name]
}

func newTestCEP(namespace, name, ip string, id int64) *types.CiliumEndpoint {
	return &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{Namespace: namespace, Name: name},
		Identity:   &cilium_api_v2.EndpointIdentity{ID: id},
		Networking: &cilium_api_v2.EndpointNetworking{
			NodeIP:     "172.18.0.2",
			Addressing: cilium_api_v2.AddressPairList{{IPV4: ip}},
		},
	}
}

func cepEvent(kind resource.EventKind, cep *types.CiliumEndpoint) resource.Event[*types.CiliumEndpoint] {
	return resource.Event[*types.CiliumEndpoint]{
		Kind: kind, Key: resource.NewKey(cep), Object: cep, Done: func(error) {},
	}
}

func nsEvent(kind resource.EventKind, name string) resource.Event[*slim_corev1.Namespace] {
	ns := &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{Name: name}}
	return resource.Event[*slim_corev1.Namespace]{
		Kind: kind, Key: resource.NewKey(ns), Object: ns, Done: func(error) {},
	}
}

type syncLoopFixture struct {
	loop      *syncLoop[*types.CiliumEndpoint]
	resources *fakeCEPStore
	kvstore   *fakeSyncStore
	nsmgr     *fakeNamespaceManager
}

func newSyncLoopFixture(t *testing.T) *syncLoopFixture {
	f := &syncLoopFixture{
		resources: newFakeCEPStore(),
		kvstore:   newFakeSyncStore(),
		nsmgr:     &fakeNamespaceManager{nonGlobal: make(map[string]bool)},
	}

	f.loop = &syncLoop[*types.CiliumEndpoint]{
		logger:           hivetest.Logger(t),
		namespaced:       true,
		converter:        NewCachedConverter(ciliumEndpointMapper),
		namespaceManager: f.nsmgr,
		namespacer:       newCiliumEndpointNamespacer(),
		store:            f.kvstore,
		resourceStore:    f.resources,
		synced:           func(context.Context) {},
		seen:             sets.New[resource.Key](),
	}

	return f
}

const testIP = "10.244.1.79"

// TestSyncLoopNamespaceEventLostDelete reproduces the case in which a namespace
// event causes the upsertion of a resource that the resource subscriber has not
// emitted yet. If the resource is then deleted before the subscriber processes
// it, the subscriber does not emit any delete event (as it never emitted the
// corresponding upsert), hence permanently leaking the kvstore entry.
func TestSyncLoopNamespaceEventLostDelete(t *testing.T) {
	ctx := t.Context()
	f := newSyncLoopFixture(t)

	// The resource is in the store, but the subscriber has not emitted it yet.
	old := newTestCEP("mortar", "job", testIP, 1000)
	f.resources.add(old)

	// A namespace event is received for the namespace of the resource.
	f.loop.handleNamespace(ctx, nsEvent(resource.Upsert, "mortar"))

	// The resource is then deleted before the subscriber emits it. Given that
	// the subscriber never emitted the upsert event, it does not emit the delete
	// event either. Hence, there's no corresponding handleResource call here.
	f.resources.remove(old)

	// A new resource claims the same IP.
	cur := newTestCEP("tyrantrum-k8s", "clustermesh-apiserver", testIP, 2000)
	f.resources.add(cur)
	f.loop.handleResource(ctx, cepEvent(resource.Upsert, cur))

	owner, ok := f.kvstore.owner(t, testIP)
	require.True(t, ok)
	require.Equal(t, "tyrantrum-k8s/clustermesh-apiserver", owner,
		"The IP should be associated with the only existing resource")
}

// TestSyncLoopNamespaceTransitions asserts that resources are correctly
// propagated when their namespace transitions between global and non-global.
func TestSyncLoopNamespaceTransitions(t *testing.T) {
	ctx := t.Context()
	f := newSyncLoopFixture(t)

	// The resource is initially in a non-global namespace, hence not propagated,
	// although the subscriber did emit it.
	f.nsmgr.nonGlobal["quixote"] = true
	cep := newTestCEP("quixote", "cep", testIP, 1000)
	f.resources.add(cep)
	f.loop.handleResource(ctx, cepEvent(resource.Upsert, cep))
	require.Empty(t, f.kvstore.kvs)

	// The namespace becomes global, and the resource should be propagated.
	delete(f.nsmgr.nonGlobal, "quixote")
	f.loop.handleNamespace(ctx, nsEvent(resource.Upsert, "quixote"))
	owner, ok := f.kvstore.owner(t, testIP)
	require.True(t, ok)
	require.Equal(t, "quixote/cep", owner)

	// The namespace becomes non-global again, and the resource should be removed.
	f.nsmgr.nonGlobal["quixote"] = true
	f.loop.handleNamespace(ctx, nsEvent(resource.Upsert, "quixote"))
	require.Empty(t, f.kvstore.kvs)

	// The namespace becomes global again, and the resource should be propagated.
	delete(f.nsmgr.nonGlobal, "quixote")
	f.loop.handleNamespace(ctx, nsEvent(resource.Upsert, "quixote"))
	owner, ok = f.kvstore.owner(t, testIP)
	require.True(t, ok)
	require.Equal(t, "quixote/cep", owner)

	// The namespace is deleted, and the resource should be removed.
	f.loop.handleNamespace(ctx, nsEvent(resource.Delete, "quixote"))
	require.Empty(t, f.kvstore.kvs)
}

// TestSyncLoopNamespaceEventUnseen asserts that namespace events ignore the
// resources not yet emitted by the subscriber, which are then propagated once
// the corresponding upsert event is received.
func TestSyncLoopNamespaceEventUnseen(t *testing.T) {
	ctx := t.Context()
	f := newSyncLoopFixture(t)

	cep := newTestCEP("quixote", "cep", testIP, 1000)
	f.resources.add(cep)

	f.loop.handleNamespace(ctx, nsEvent(resource.Upsert, "quixote"))
	require.Empty(t, f.kvstore.kvs)

	f.loop.handleResource(ctx, cepEvent(resource.Upsert, cep))
	owner, ok := f.kvstore.owner(t, testIP)
	require.True(t, ok)
	require.Equal(t, "quixote/cep", owner)

	// Once deleted, the resource should no longer be considered by namespace
	// events, even if (unexpectedly) still present in the store.
	f.loop.handleResource(ctx, cepEvent(resource.Delete, cep))
	require.Empty(t, f.kvstore.kvs)

	f.loop.handleNamespace(ctx, nsEvent(resource.Upsert, "quixote"))
	require.Empty(t, f.kvstore.kvs)
}

// TestSyncLoopNamespaceLookupRetry asserts that resources whose upsert event
// is retried due to a failure determining the namespace status are still
// resynchronized by namespace events, as the subscriber guarantees the
// emission of the corresponding delete event.
func TestSyncLoopNamespaceLookupRetry(t *testing.T) {
	ctx := t.Context()
	f := newSyncLoopFixture(t)

	cep := newTestCEP("quixote", "cep", testIP, 1000)
	f.resources.add(cep)

	var retried bool
	event := cepEvent(resource.Upsert, cep)
	event.Done = func(err error) { retried = err != nil }

	f.nsmgr.err = errors.New("namespace not found")
	f.loop.handleResource(ctx, event)
	require.True(t, retried, "The event should have been retried")
	require.Empty(t, f.kvstore.kvs)

	// The namespace is created, and the resource propagated.
	f.nsmgr.err = nil
	f.loop.handleNamespace(ctx, nsEvent(resource.Upsert, "quixote"))
	owner, ok := f.kvstore.owner(t, testIP)
	require.True(t, ok)
	require.Equal(t, "quixote/cep", owner)

	// The resource is deleted.
	f.resources.remove(cep)
	f.loop.handleResource(ctx, cepEvent(resource.Delete, cep))
	require.Empty(t, f.kvstore.kvs)
}
