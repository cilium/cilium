// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

var (
	etcdOpts = map[string]string{EtcdRateLimitOption: "100"}
)

func TestLock(t *testing.T) {
	testutils.IntegrationTest(t)
	SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testLock(t)
}

func testLock(t *testing.T) {
	prefix := "locktest/"

	for i := range 10 {
		lock, err := LockPath(context.Background(), hivetest.Logger(t), Client(), fmt.Sprintf("%sfoo/%d", prefix, i))
		require.NoError(t, err)
		require.NotNil(t, lock)
		lock.Unlock(context.TODO())
	}
}

func testKey(prefix string, i int) string {
	return fmt.Sprintf("%s%s/%010d", prefix, "foo", i)
}

func testValue(i int) string {
	return fmt.Sprintf("blah %d blah %d", i, i)
}

func TestGetSet(t *testing.T) {
	testutils.IntegrationTest(t)
	SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testGetSet(t)
}

func testGetSet(t *testing.T) {
	prefix := "unit-test/"
	maxID := 8

	pairs, err := Client().ListPrefix(context.Background(), prefix)
	require.NoError(t, err)
	require.Empty(t, pairs)

	for i := range maxID {
		val, err := Client().Get(context.TODO(), testKey(prefix, i))
		require.NoError(t, err)
		require.Nil(t, val)

		require.NoError(t, Client().Update(context.TODO(), testKey(prefix, i), []byte(testValue(i)), false))

		val, err = Client().Get(context.TODO(), testKey(prefix, i))
		require.NoError(t, err)
		require.Equal(t, testValue(i), string(val))
	}

	pairs, err = Client().ListPrefix(context.Background(), prefix)
	require.NoError(t, err)
	require.Len(t, pairs, maxID)

	for i := range maxID {
		require.NoError(t, Client().Delete(context.TODO(), testKey(prefix, i)))

		val, err := Client().Get(context.TODO(), testKey(prefix, i))
		require.NoError(t, err)
		require.Nil(t, val)
	}

	pairs, err = Client().ListPrefix(context.Background(), prefix)
	require.NoError(t, err)
	require.Empty(t, pairs)
}

func BenchmarkGet(b *testing.B) {
	testutils.IntegrationTest(b)
	SetupDummyWithConfigOpts(b, "etcd", etcdOpts)
	benchmarkGet(b)
}

func benchmarkGet(b *testing.B) {
	prefix := "unit-test/"

	key := testKey(prefix, 1)
	require.NoError(b, Client().Update(context.TODO(), key, []byte(testValue(100)), false))

	for b.Loop() {
		_, err := Client().Get(context.TODO(), key)
		require.NoError(b, err)
	}
}

func BenchmarkSet(b *testing.B) {
	testutils.IntegrationTest(b)
	SetupDummyWithConfigOpts(b, "etcd", etcdOpts)
	benchmarkSet(b)
}

func benchmarkSet(b *testing.B) {
	prefix := "unit-test/"

	key, val := testKey(prefix, 1), testValue(100)

	for b.Loop() {
		require.NoError(b, Client().Update(context.TODO(), key, []byte(val), false))
	}
}

func TestUpdate(t *testing.T) {
	testutils.IntegrationTest(t)
	SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testUpdate(t)
}

func testUpdate(t *testing.T) {
	prefix := "unit-test/"

	// create
	require.NoError(t, Client().Update(context.Background(), testKey(prefix, 0), []byte(testValue(0)), true))

	val, err := Client().Get(context.TODO(), testKey(prefix, 0))
	require.NoError(t, err)
	require.Equal(t, testValue(0), string(val))

	// update
	require.NoError(t, Client().Update(context.Background(), testKey(prefix, 0), []byte(testValue(0)), true))

	val, err = Client().Get(context.TODO(), testKey(prefix, 0))
	require.NoError(t, err)
	require.Equal(t, testValue(0), string(val))
}

func TestCreateOnly(t *testing.T) {
	testutils.IntegrationTest(t)
	SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testCreateOnly(t)
}

func testCreateOnly(t *testing.T) {
	prefix := "unit-test/"

	success, err := Client().CreateOnly(context.Background(), testKey(prefix, 0), []byte(testValue(0)), false)
	require.NoError(t, err)
	require.True(t, success)

	val, err := Client().Get(context.TODO(), testKey(prefix, 0))
	require.NoError(t, err)
	require.Equal(t, testValue(0), string(val))

	success, err = Client().CreateOnly(context.Background(), testKey(prefix, 0), []byte(testValue(1)), false)
	require.NoError(t, err)
	require.False(t, success)

	val, err = Client().Get(context.TODO(), testKey(prefix, 0))
	require.NoError(t, err)
	require.Equal(t, testValue(0), string(val))
}

func expectEvent(t *testing.T, events EventChan, typ EventType, key string, val string) {
	select {
	case event := <-events:
		require.Equal(t, typ, event.Typ)

		if event.Typ != EventTypeListDone {
			require.Equal(t, key, event.Key)
			// etcd does not provide the value of deleted keys so we can't check it.
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout while waiting for kvstore watcher event")
	}
}

func TestListAndWatch(t *testing.T) {
	testutils.IntegrationTest(t)
	SetupDummyWithConfigOpts(t, "etcd", etcdOpts)
	testListAndWatch(t)
}

func testListAndWatch(t *testing.T) {
	key1, key2 := "foo2/key1", "foo2/key2"
	val1, val2 := "val1", "val2"

	success, err := Client().CreateOnly(context.Background(), key1, []byte(val1), false)
	require.NoError(t, err)
	require.True(t, success)

	ctx, cancel := context.WithCancel(context.Background())
	events := Client().ListAndWatch(ctx, "foo2/")
	require.NotNil(t, t)

	expectEvent(t, events, EventTypeCreate, key1, val1)
	expectEvent(t, events, EventTypeListDone, "", "")

	success, err = Client().CreateOnly(context.Background(), key2, []byte(val2), false)
	require.NoError(t, err)
	require.True(t, success)
	expectEvent(t, events, EventTypeCreate, key2, val2)

	err = Client().Delete(context.TODO(), key1)
	require.NoError(t, err)
	expectEvent(t, events, EventTypeDelete, key1, val1)

	success, err = Client().CreateOnly(context.Background(), key1, []byte(val1), false)
	require.NoError(t, err)
	require.True(t, success)
	expectEvent(t, events, EventTypeCreate, key1, val1)

	err = Client().Delete(context.TODO(), key1)
	require.NoError(t, err)
	expectEvent(t, events, EventTypeDelete, key1, val1)

	err = Client().Delete(context.TODO(), key2)
	require.NoError(t, err)
	expectEvent(t, events, EventTypeDelete, key2, val2)

	cancel()

	// Wait for the Events channel to be closed
	_, ok := <-events
	require.False(t, ok, "Received unexpected event")
}
