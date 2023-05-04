// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type KVPair struct{ Key, Value string }

func NewKVPair(key, value string) *KVPair      { return &KVPair{Key: key, Value: value} }
func (kv *KVPair) GetKeyName() string          { return kv.Key }
func (kv *KVPair) Marshal() ([]byte, error)    { return []byte(kv.Value), nil }
func (kv *KVPair) Unmarshal(data []byte) error { return nil /* not used */ }

type fakeBackend struct {
	t           *testing.T
	expectLease bool

	updated chan *KVPair
	deleted chan *KVPair

	errorsOnUpdate map[string]uint
	errorsOnDelete map[string]uint
}

func NewFakeBackend(t *testing.T, expectLease bool) *fakeBackend {
	return &fakeBackend{
		t:           t,
		expectLease: expectLease,

		updated: make(chan *KVPair),
		deleted: make(chan *KVPair),

		errorsOnUpdate: make(map[string]uint),
		errorsOnDelete: make(map[string]uint),
	}
}

func (fb *fakeBackend) Update(ctx context.Context, key string, value []byte, lease bool) error {
	if lease != fb.expectLease {
		key = "error"
		value = []byte(fmt.Sprintf("incorrect lease setting, expected(%v) - found(%v)", fb.expectLease, lease))
	}

	select {
	case fb.updated <- NewKVPair(key, string(value)):
	case <-ctx.Done():
		require.Failf(fb.t, "Context closed before writing to updated channel", "key: %s, value: %s", key, value)
	}

	if cnt := fb.errorsOnUpdate[key]; cnt > 0 {
		fb.errorsOnUpdate[key]--
		return errors.New("failing on purpose")
	}

	return nil
}

func (fb *fakeBackend) Delete(ctx context.Context, key string) error {
	select {
	case fb.deleted <- NewKVPair(key, ""):
	case <-ctx.Done():
		require.Failf(fb.t, "Context closed before writing to deleted channel", "key: %s", key)
	}

	if cnt := fb.errorsOnDelete[key]; cnt > 0 {
		fb.errorsOnDelete[key]--
		return errors.New("failing on purpose")
	}

	return nil
}

type fakeRateLimiter struct{ whenCalled, forgetCalled chan *KVPair }

func NewFakeRateLimiter() *fakeRateLimiter {
	return &fakeRateLimiter{whenCalled: make(chan *KVPair), forgetCalled: make(chan *KVPair)}
}

func (frl *fakeRateLimiter) When(item interface{}) time.Duration {
	frl.whenCalled <- NewKVPair(item.(string), "")
	return time.Duration(0)
}
func (frl *fakeRateLimiter) Forget(item interface{}) {
	frl.forgetCalled <- NewKVPair(item.(string), "")
}
func (frl *fakeRateLimiter) NumRequeues(item interface{}) int { return 0 }

func eventually(in <-chan *KVPair, timeout time.Duration) *KVPair {
	select {
	case kv := <-in:
		return kv
	case <-time.After(timeout):
		return NewKVPair("error", "timed out waiting for KV")
	}
}

func TestWorkqueueSyncStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, true)
	store := NewWorkqueueSyncStore(backend, "/foo/bar")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	// Upserts should trigger the corresponding backend operation.
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	store.UpsertKey(ctx, NewKVPair("key2", "value2"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated, 100*time.Millisecond))
	require.Equal(t, NewKVPair("/foo/bar/key2", "value2"), eventually(backend.updated, 100*time.Millisecond))

	// Unless the pair is already part of the known state.
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	store.UpsertKey(ctx, NewKVPair("key3", "value3"))
	require.Equal(t, NewKVPair("/foo/bar/key3", "value3"), eventually(backend.updated, 100*time.Millisecond))

	// Upserts for the same key should be coalescenced. In this case, it is guaranteed
	// to happen since the first upsert blocks until we read from the channel.
	store.UpsertKey(ctx, NewKVPair("key4", "value4"))
	store.UpsertKey(ctx, NewKVPair("key1", "valueA"))
	store.UpsertKey(ctx, NewKVPair("key1", "valueB"))
	require.Equal(t, NewKVPair("/foo/bar/key4", "value4"), eventually(backend.updated, 100*time.Millisecond))
	require.Equal(t, NewKVPair("/foo/bar/key1", "valueB"), eventually(backend.updated, 100*time.Millisecond))

	// Deletions should trigger the corresponding backend operation, only if known to exist.
	store.DeleteKey(ctx, NewKVPair("key5", ""))
	store.DeleteKey(ctx, NewKVPair("key4", ""))
	require.Equal(t, NewKVPair("/foo/bar/key4", ""), eventually(backend.deleted, 100*time.Millisecond))

	// Both upserts and deletes should be retried in case an error is returned by the client
	backend.errorsOnUpdate["/foo/bar/key1"] = 1
	store.UpsertKey(ctx, NewKVPair("key1", "valueC"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "valueC"), eventually(backend.updated, 100*time.Millisecond))
	require.Equal(t, NewKVPair("/foo/bar/key1", "valueC"), eventually(backend.updated, 250*time.Millisecond))

	backend.errorsOnDelete["/foo/bar/key2"] = 1
	store.DeleteKey(ctx, NewKVPair("key2", ""))
	require.Equal(t, NewKVPair("/foo/bar/key2", ""), eventually(backend.deleted, 100*time.Millisecond))
	require.Equal(t, NewKVPair("/foo/bar/key2", ""), eventually(backend.deleted, 250*time.Millisecond))
}

func TestWorkqueueSyncStoreWithoutLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, false)
	store := NewWorkqueueSyncStore(backend, "/foo/bar", WSSWithoutLease())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	// The fake backend checks whether the lease setting corresponds to the expected
	// value, and emits a KVPair with the error message in case it does not match
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated, 100*time.Millisecond))
}

func TestWorkqueueSyncStoreWithRateLimiter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, true)
	limiter := NewFakeRateLimiter()
	store := NewWorkqueueSyncStore(backend, "/foo/bar", WSSWithRateLimiter(limiter))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	backend.errorsOnUpdate["/foo/bar/key1"] = 1

	// Assert that the custom rate limiter has been correctly called
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated, 100*time.Millisecond))
	require.Equal(t, NewKVPair("key1", ""), eventually(limiter.whenCalled, 100*time.Millisecond))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated, 100*time.Millisecond))
	require.Equal(t, NewKVPair("key1", ""), eventually(limiter.forgetCalled, 100*time.Millisecond))
}

func TestWorkqueueSyncStoreWithWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, true)
	store := NewWorkqueueSyncStore(backend, "/foo/bar", WSSWithWorkers(2))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated, 100*time.Millisecond))

	// Since the Update() and Delete() functions implemented by the fake backend
	// block until we read from the correposponding channel, reading in reversed
	// order the elements from the two channels requires at least two workers
	store.DeleteKey(ctx, NewKVPair("key1", "value1"))
	store.UpsertKey(ctx, NewKVPair("key2", "value2"))
	require.Equal(t, NewKVPair("/foo/bar/key2", "value2"), eventually(backend.updated, 100*time.Millisecond))
	require.Equal(t, NewKVPair("/foo/bar/key1", ""), eventually(backend.deleted, 100*time.Millisecond))
}
