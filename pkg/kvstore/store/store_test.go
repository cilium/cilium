// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	testPrefix           = "store-tests"
	sharedKeyDeleteDelay = time.Second
)

type TestType struct {
	Name string
}

var _ = TestType{}

func (t *TestType) GetKeyName() string                    { return t.Name }
func (t *TestType) DeepKeyCopy() LocalKey                 { return &TestType{Name: t.Name} }
func (t *TestType) Marshal() ([]byte, error)              { return json.Marshal(t) }
func (t *TestType) Unmarshal(_ string, data []byte) error { return json.Unmarshal(data, t) }

type opCounter struct {
	deleted int
	updated int
}

var (
	counter     = map[string]*opCounter{}
	counterLock lock.RWMutex
)

func (t *TestType) deleted() int {
	counterLock.RLock()
	defer counterLock.RUnlock()
	return counter[t.Name].deleted
}

func (t *TestType) updated() int {
	counterLock.RLock()
	defer counterLock.RUnlock()
	return counter[t.Name].updated
}

func initTestType(name string) TestType {
	t := TestType{}
	t.Name = name
	counterLock.Lock()
	counter[name] = &opCounter{}
	counterLock.Unlock()
	return t
}

type observer struct{}

func (o *observer) OnUpdate(k Key) {
	counterLock.Lock()
	if c, ok := counter[k.(*TestType).Name]; ok {
		c.updated++
	}
	counterLock.Unlock()
}
func (o *observer) OnDelete(k NamedKey) {
	counterLock.Lock()
	counter[k.(*TestType).Name].deleted++
	counterLock.Unlock()
}

func newTestType() Key {
	t := TestType{}
	return &t
}

func TestStoreCreation(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	testStoreCreation(t)
}

func testStoreCreation(t *testing.T) {
	// Missing Prefix must result in error
	store, err := JoinSharedStore(Configuration{})
	require.ErrorContains(t, err, "prefix must be specified")
	require.Nil(t, store)

	// Missing KeyCreator must result in error
	store, err = JoinSharedStore(Configuration{Prefix: rand.String(12)})
	require.ErrorContains(t, err, "KeyCreator must be specified")
	require.Nil(t, store)

	// Basic creation should result in default values
	store, err = JoinSharedStore(Configuration{Prefix: rand.String(12), KeyCreator: newTestType})
	require.NoError(t, err)
	require.NotNil(t, store)
	require.Equal(t, option.Config.KVstorePeriodicSync, store.conf.SynchronizationInterval)
	store.Close(context.TODO())

	// Test with kvstore client specified
	store, err = JoinSharedStore(Configuration{Prefix: rand.String(12), KeyCreator: newTestType, Backend: kvstore.Client()})
	require.NoError(t, err)
	require.NotNil(t, store)
	require.Equal(t, option.Config.KVstorePeriodicSync, store.conf.SynchronizationInterval)
	store.Close(context.TODO())
}

func TestStoreOperations(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	testStoreOperations(t)
}

func testStoreOperations(t *testing.T) {
	// Basic creation should result in default values
	store, err := JoinSharedStore(Configuration{
		Prefix:               rand.String(12),
		KeyCreator:           newTestType,
		Observer:             &observer{},
		SharedKeyDeleteDelay: sharedKeyDeleteDelay,
	})
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close(context.TODO())

	localKey1 := initTestType("local1")
	localKey2 := initTestType("local2")
	localKey3 := initTestType("local3")

	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	require.NoError(t, err)
	err = store.UpdateLocalKeySync(context.TODO(), &localKey2)
	require.NoError(t, err)

	// due to the short sync interval, it is possible that multiple updates
	// have occurred, make the test reliable by succeeding on at lest one
	// update
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.GreaterOrEqual(c, localKey1.updated(), 1) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.GreaterOrEqual(c, localKey2.updated(), 1) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 0, localKey3.updated()) }, timeout, tick)

	store.DeleteLocalKey(context.TODO(), &localKey1)
	// localKey1 will be deleted 2 times, one from local key and other from
	// the kvstore watcher
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 2, localKey1.deleted()) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 0, localKey2.deleted()) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 0, localKey3.deleted()) }, timeout, tick)

	store.DeleteLocalKey(context.TODO(), &localKey3)
	// localKey3 won't be deleted because it was never added
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 0, localKey3.deleted()) }, timeout, tick)

	store.DeleteLocalKey(context.TODO(), &localKey2)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 2, localKey1.deleted()) }, timeout, tick)
	// localKey2 will be deleted 2 times, one from local key and other from
	// the kvstore watcher
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 2, localKey2.deleted()) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 0, localKey3.deleted()) }, timeout, tick)
}

func TestStorePeriodicSync(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	testStorePeriodicSync(t)
}

func testStorePeriodicSync(t *testing.T) {
	// Create a store with a very short periodic sync interval
	store, err := JoinSharedStore(Configuration{
		Prefix:                  rand.String(12),
		KeyCreator:              newTestType,
		SynchronizationInterval: 10 * time.Millisecond,
		SharedKeyDeleteDelay:    defaults.NodeDeleteDelay,
		Observer:                &observer{},
	})
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close(context.TODO())

	localKey1 := initTestType("local1")
	localKey2 := initTestType("local2")

	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	require.NoError(t, err)
	err = store.UpdateLocalKeySync(context.TODO(), &localKey2)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.GreaterOrEqual(c, localKey1.updated(), 1) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.GreaterOrEqual(c, localKey2.updated(), 1) }, timeout, tick)

	store.DeleteLocalKey(context.TODO(), &localKey1)
	store.DeleteLocalKey(context.TODO(), &localKey2)

	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 1, localKey1.deleted()) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.EqualValues(c, 1, localKey2.deleted()) }, timeout, tick)
}

func TestStoreLocalKeyProtection(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	testStoreLocalKeyProtection(t)
}

func testStoreLocalKeyProtection(t *testing.T) {
	store, err := JoinSharedStore(Configuration{
		Prefix:                  rand.String(12),
		KeyCreator:              newTestType,
		SynchronizationInterval: time.Hour, // ensure that periodic sync does not interfer
		Observer:                &observer{},
	})
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close(context.TODO())

	localKey1 := initTestType("local1")

	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.GreaterOrEqual(c, localKey1.updated(), 1) }, timeout, tick)
	// delete all keys
	kvstore.Client().DeletePrefix(context.TODO(), store.conf.Prefix)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		v, err := kvstore.Client().Get(context.TODO(), store.keyPath(&localKey1))
		assert.NoError(c, err)
		assert.NotNil(c, v)
	}, timeout, tick)
}

func setupStoreCollaboration(t *testing.T, storePrefix, keyPrefix string) *SharedStore {
	store, err := JoinSharedStore(Configuration{
		Prefix:                  storePrefix,
		KeyCreator:              newTestType,
		SynchronizationInterval: time.Second,
		Observer:                &observer{},
	})
	require.NoError(t, err)
	require.NotNil(t, store)

	localKey1 := initTestType(keyPrefix + "-local1")
	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	require.NoError(t, err)

	localKey2 := initTestType(keyPrefix + "-local2")
	err = store.UpdateLocalKeySync(context.TODO(), &localKey2)
	require.NoError(t, err)

	// wait until local keys was inserted and until the kvstore has confirmed the
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.GreaterOrEqual(c, localKey1.updated(), 1) }, timeout, tick)
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.GreaterOrEqual(c, localKey2.updated(), 1) }, timeout, tick)

	require.Len(t, store.getLocalKeys(), 2)

	return store
}

func TestStoreCollaboration(t *testing.T) {
	testutils.IntegrationTest(t)
	kvstore.SetupDummy(t, "etcd")
	testStoreCollaboration(t)
}

func testStoreCollaboration(t *testing.T) {
	storePrefix := rand.String(12)

	collab1 := setupStoreCollaboration(t, storePrefix, rand.String(12))
	defer collab1.Close(context.TODO())

	collab2 := setupStoreCollaboration(t, storePrefix, rand.String(12))
	defer collab2.Close(context.TODO())

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		all := append(collab1.getLocalKeys(), collab2.getLocalKeys()...)
		assert.ElementsMatch(c, collab1.getSharedKeys(), all)
		assert.ElementsMatch(c, collab2.getSharedKeys(), all)
	}, timeout, tick)
}

// getLocalKeys returns all local keys
func (s *SharedStore) getLocalKeys() []Key {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]Key, len(s.localKeys))
	idx := 0
	for _, key := range s.localKeys {
		keys[idx] = key
		idx++
	}

	return keys
}

// getSharedKeys returns all shared keys
func (s *SharedStore) getSharedKeys() []Key {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]Key, len(s.sharedKeys))
	idx := 0
	for _, key := range s.sharedKeys {
		keys[idx] = key
		idx++
	}

	return keys
}
