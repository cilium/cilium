// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package instances

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
)

const testTimeout = 10 * time.Second

type testInterface struct {
	id string
}

func (t *testInterface) InterfaceID() string                    { return t.id }
func (t *testInterface) DeepCopyInterface() ipamTypes.Interface { return &testInterface{id: t.id} }

func instanceWith(ifaceIDs ...string) *ipamTypes.Instance {
	instance := &ipamTypes.Instance{Interfaces: map[string]ipamTypes.Interface{}}
	for _, id := range ifaceIDs {
		instance.Interfaces[id] = &testInterface{id: id}
	}
	return instance
}

func mapWith(instanceIDs ...string) *ipamTypes.InstanceMap {
	m := ipamTypes.NewInstanceMap()
	for _, id := range instanceIDs {
		m.UpdateInstance(id, instanceWith(id+"-iface"))
	}
	return m
}

func cachedInterfaceIDs(c *InstanceCache, instanceID string) (ids []string) {
	c.ForeachInstance(instanceID, func(_, ifaceID string, _ ipamTypes.Interface) error {
		ids = append(ids, ifaceID)
		return nil
	})
	return ids
}

func TestInstanceCacheBasicOperations(t *testing.T) {
	c := NewInstanceCacheFrom(mapWith("i-1", "i-2"))

	require.True(t, c.HasInstance("i-1"))
	require.True(t, c.HasInstance("i-2"))
	require.False(t, c.HasInstance("i-3"))

	require.ElementsMatch(t, []string{"i-1-iface"}, cachedInterfaceIDs(c, "i-1"))

	c.UpdateInstance("i-1", func(instances *ipamTypes.InstanceMap) {
		instances.Update("i-1", &testInterface{id: "i-1-iface2"})
	})
	require.ElementsMatch(t, []string{"i-1-iface", "i-1-iface2"}, cachedInterfaceIDs(c, "i-1"))

	c.UpdateInterface("i-1", &testInterface{id: "i-1-iface3"})
	require.ElementsMatch(t, []string{"i-1-iface", "i-1-iface2", "i-1-iface3"}, cachedInterfaceIDs(c, "i-1"))

	// UpdateInterface must not recreate an instance that is not cached.
	c.UpdateInterface("i-gone", &testInterface{id: "i-gone-iface"})
	require.False(t, c.HasInstance("i-gone"))

	c.DeleteInstance("i-2")
	require.False(t, c.HasInstance("i-2"))

	var seen bool
	c.Read(func(instances *ipamTypes.InstanceMap) {
		seen = instances.Exists("i-1")
	})
	require.True(t, seen)
}

func TestInstanceCacheFullResync(t *testing.T) {
	c := NewInstanceCacheFrom(mapWith("i-old"))

	var published bool
	start, err := c.FullResync(t.Context(), func(ctx context.Context) (*ipamTypes.InstanceMap, PublishFunc, error) {
		return mapWith("i-new"), func() { published = true }, nil
	})
	require.NoError(t, err)
	require.False(t, start.IsZero())
	require.True(t, published)
	require.False(t, c.HasInstance("i-old"))
	require.True(t, c.HasInstance("i-new"))
}

func TestInstanceCacheFullResyncError(t *testing.T) {
	c := NewInstanceCacheFrom(mapWith("i-1"))

	fetchErr := errors.New("cloud API down")
	start, err := c.FullResync(t.Context(), func(ctx context.Context) (*ipamTypes.InstanceMap, PublishFunc, error) {
		return nil, nil, fetchErr
	})
	require.ErrorIs(t, err, fetchErr)
	require.True(t, start.IsZero())
	// The cache is left untouched.
	require.True(t, c.HasInstance("i-1"))
}

func TestInstanceCacheInstanceSync(t *testing.T) {
	c := NewInstanceCacheFrom(mapWith("i-1"))

	var published bool
	start, err := c.InstanceSync(t.Context(), "i-2", func(ctx context.Context) (*ipamTypes.Instance, PublishFunc, error) {
		return instanceWith("i-2-iface"), func() { published = true }, nil
	})
	require.NoError(t, err)
	require.False(t, start.IsZero())
	require.True(t, published)
	require.True(t, c.HasInstance("i-1"))
	require.True(t, c.HasInstance("i-2"))

	fetchErr := errors.New("cloud API down")
	_, err = c.InstanceSync(t.Context(), "i-3", func(ctx context.Context) (*ipamTypes.Instance, PublishFunc, error) {
		return nil, nil, fetchErr
	})
	require.ErrorIs(t, err, fetchErr)
	require.False(t, c.HasInstance("i-3"))
}

// TestInstanceCacheUpdateDuringFullResync checks that a cache update made
// while a full resync is fetching from the cloud API waits for the resync and
// survives it, instead of being overwritten by the fetched state.
func TestInstanceCacheUpdateDuringFullResync(t *testing.T) {
	c := NewInstanceCacheFrom(mapWith("i-1"))

	inFetch := make(chan struct{})
	finishFetch := make(chan struct{})
	resyncDone := make(chan error, 1)
	go func() {
		_, err := c.FullResync(t.Context(), func(ctx context.Context) (*ipamTypes.InstanceMap, PublishFunc, error) {
			close(inFetch)
			<-finishFetch
			// The fetched state does not contain the concurrent updates.
			return mapWith("i-1"), nil, nil
		})
		resyncDone <- err
	}()

	select {
	case <-inFetch:
	case <-time.After(testTimeout):
		t.Fatal("full resync did not reach its fetch function")
	}

	updateDone := make(chan struct{})
	deleteDone := make(chan struct{})
	go func() {
		defer close(updateDone)
		c.UpdateInstance("i-1", func(instances *ipamTypes.InstanceMap) {
			instances.Update("i-1", &testInterface{id: "i-1-attached"})
		})
	}()
	go func() {
		defer close(deleteDone)
		c.DeleteInstance("i-2")
	}()

	// Neither update may complete while the full resync holds the resync lock.
	select {
	case <-updateDone:
		t.Fatal("UpdateInstance completed during a full resync")
	case <-deleteDone:
		t.Fatal("DeleteInstance completed during a full resync")
	case <-time.After(100 * time.Millisecond):
	}

	close(finishFetch)
	require.NoError(t, <-resyncDone)

	for _, done := range []chan struct{}{updateDone, deleteDone} {
		select {
		case <-done:
		case <-time.After(testTimeout):
			t.Fatal("cache update still blocked after the full resync completed")
		}
	}

	// The update was applied on top of the resynced state.
	require.ElementsMatch(t, []string{"i-1-iface", "i-1-attached"}, cachedInterfaceIDs(c, "i-1"))
}

// TestInstanceCacheInstanceSyncsRunInParallel checks that two incremental
// instance syncs can fetch concurrently.
func TestInstanceCacheInstanceSyncsRunInParallel(t *testing.T) {
	c := NewInstanceCache()

	inFetch := make(chan string, 2)
	finishFetch := make(chan struct{})
	syncDone := make(chan error, 2)
	for _, id := range []string{"i-1", "i-2"} {
		go func() {
			_, err := c.InstanceSync(t.Context(), id, func(ctx context.Context) (*ipamTypes.Instance, PublishFunc, error) {
				inFetch <- id
				<-finishFetch
				return instanceWith(id + "-iface"), nil, nil
			})
			syncDone <- err
		}()
	}

	// Both syncs sit in their fetch at the same time.
	for range 2 {
		select {
		case <-inFetch:
		case <-time.After(testTimeout):
			t.Fatal("instance syncs did not fetch in parallel")
		}
	}

	close(finishFetch)
	for range 2 {
		require.NoError(t, <-syncDone)
	}
	require.True(t, c.HasInstance("i-1"))
	require.True(t, c.HasInstance("i-2"))
}

// TestInstanceCacheInstanceSyncBlocksFullResync checks that a full resync
// waits for an in-flight incremental instance sync.
func TestInstanceCacheInstanceSyncBlocksFullResync(t *testing.T) {
	c := NewInstanceCache()

	inFetch := make(chan struct{})
	finishFetch := make(chan struct{})
	syncDone := make(chan error, 1)
	go func() {
		_, err := c.InstanceSync(t.Context(), "i-1", func(ctx context.Context) (*ipamTypes.Instance, PublishFunc, error) {
			close(inFetch)
			<-finishFetch
			return instanceWith("i-1-iface"), nil, nil
		})
		syncDone <- err
	}()

	select {
	case <-inFetch:
	case <-time.After(testTimeout):
		t.Fatal("instance sync did not reach its fetch function")
	}

	resyncDone := make(chan error, 1)
	go func() {
		_, err := c.FullResync(t.Context(), func(ctx context.Context) (*ipamTypes.InstanceMap, PublishFunc, error) {
			// The fetch only runs once the instance sync has published, so
			// it sees the instance.
			return mapWith("i-1"), nil, nil
		})
		resyncDone <- err
	}()

	select {
	case <-resyncDone:
		t.Fatal("full resync completed during an instance sync")
	case <-time.After(100 * time.Millisecond):
	}

	close(finishFetch)
	require.NoError(t, <-syncDone)
	select {
	case err := <-resyncDone:
		require.NoError(t, err)
	case <-time.After(testTimeout):
		t.Fatal("full resync still blocked after the instance sync completed")
	}

	// The full resync's fetch only ran after the instance sync published, so
	// its result contains the instance.
	require.True(t, c.HasInstance("i-1"))
}

// TestInstanceCacheUpdatesSerializedPerInstance checks that a cache update to
// an instance waits for an in-flight incremental sync of the same instance,
// so a sync whose fetch is delayed cannot overwrite a newer update, while
// updates to other instances proceed in parallel.
func TestInstanceCacheUpdatesSerializedPerInstance(t *testing.T) {
	c := NewInstanceCacheFrom(mapWith("i-1", "i-2"))

	inFetch := make(chan struct{})
	finishFetch := make(chan struct{})
	syncDone := make(chan error, 1)
	go func() {
		_, err := c.InstanceSync(t.Context(), "i-1", func(ctx context.Context) (*ipamTypes.Instance, PublishFunc, error) {
			close(inFetch)
			<-finishFetch
			// The delayed fetch result does not contain the concurrent update.
			return instanceWith("i-1-iface"), nil, nil
		})
		syncDone <- err
	}()

	select {
	case <-inFetch:
	case <-time.After(testTimeout):
		t.Fatal("instance sync did not reach its fetch function")
	}

	// An update to a different instance is not blocked by the sync.
	otherDone := make(chan struct{})
	go func() {
		defer close(otherDone)
		c.UpdateInterface("i-2", &testInterface{id: "i-2-attached"})
	}()
	select {
	case <-otherDone:
	case <-time.After(testTimeout):
		t.Fatal("update to a different instance blocked by an instance sync")
	}

	// Updates to the synced instance wait for the sync to publish.
	updateDone := make(chan struct{})
	deleteDone := make(chan struct{})
	go func() {
		defer close(updateDone)
		c.UpdateInterface("i-1", &testInterface{id: "i-1-attached"})
	}()
	go func() {
		defer close(deleteDone)
		c.DeleteInstance("i-1")
	}()
	select {
	case <-updateDone:
		t.Fatal("UpdateInterface completed during a sync of the same instance")
	case <-deleteDone:
		t.Fatal("DeleteInstance completed during a sync of the same instance")
	case <-time.After(100 * time.Millisecond):
	}

	close(finishFetch)
	require.NoError(t, <-syncDone)
	for _, done := range []chan struct{}{updateDone, deleteDone} {
		select {
		case <-done:
		case <-time.After(testTimeout):
			t.Fatal("cache update still blocked after the instance sync completed")
		}
	}

	// Both queued operations ran after the sync published: the instance ends
	// up deleted or with the attached interface, never with only the synced
	// state. UpdateInterface must not have recreated it if the delete ran last.
	if c.HasInstance("i-1") {
		require.Contains(t, cachedInterfaceIDs(c, "i-1"), "i-1-attached")
	}
}
