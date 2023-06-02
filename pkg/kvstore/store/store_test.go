// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	testPrefix           = "store-tests"
	sharedKeyDeleteDelay = time.Second
)

func Test(t *testing.T) {
	TestingT(t)
}

type StoreSuite struct{}

func (s *StoreSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

type StoreEtcdSuite struct {
	StoreSuite
}

var _ = Suite(&StoreEtcdSuite{})

func (e *StoreEtcdSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (e *StoreEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
}

func (e *StoreEtcdSuite) TearDownTest(c *C) {
	kvstore.Client().DeletePrefix(context.TODO(), testPrefix)
	kvstore.Client().Close(context.TODO())
}

type StoreConsulSuite struct {
	StoreSuite
}

var _ = Suite(&StoreConsulSuite{})

func (e *StoreConsulSuite) SetUpSuite(c *C) {
	testutils.IntegrationCheck(c)
}

func (e *StoreConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
}

func (e *StoreConsulSuite) TearDownTest(c *C) {
	kvstore.Client().DeletePrefix(context.TODO(), testPrefix)
	kvstore.Client().Close(context.TODO())
	time.Sleep(sharedKeyDeleteDelay + 5*time.Second)
}

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

func (s *StoreSuite) TestStoreCreation(c *C) {
	// Missing Prefix must result in error
	store, err := JoinSharedStore(Configuration{})
	c.Assert(err, ErrorMatches, "prefix must be specified")
	c.Assert(store, IsNil)

	// Missing KeyCreator must result in error
	store, err = JoinSharedStore(Configuration{Prefix: rand.RandomString()})
	c.Assert(err, ErrorMatches, "KeyCreator must be specified")
	c.Assert(store, IsNil)

	// Basic creation should result in default values
	store, err = JoinSharedStore(Configuration{Prefix: rand.RandomString(), KeyCreator: newTestType})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	c.Assert(store.conf.SynchronizationInterval, Equals, option.Config.KVstorePeriodicSync)
	store.Close(context.TODO())

	// Test with kvstore client specified
	store, err = JoinSharedStore(Configuration{Prefix: rand.RandomString(), KeyCreator: newTestType, Backend: kvstore.Client()})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	c.Assert(store.conf.SynchronizationInterval, Equals, option.Config.KVstorePeriodicSync)
	store.Close(context.TODO())
}

func expect(check func() bool) error {
	start := time.Now()
	for {
		if check() {
			return nil
		}

		if time.Since(start) > sharedKeyDeleteDelay+5*time.Second {
			return fmt.Errorf("timeout while waiting for expected value")
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (s *StoreSuite) TestStoreOperations(c *C) {
	// Basic creation should result in default values
	store, err := JoinSharedStore(Configuration{
		Prefix:               rand.RandomString(),
		KeyCreator:           newTestType,
		Observer:             &observer{},
		SharedKeyDeleteDelay: sharedKeyDeleteDelay,
	})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	defer store.Close(context.TODO())

	localKey1 := initTestType("local1")
	localKey2 := initTestType("local2")
	localKey3 := initTestType("local3")

	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	c.Assert(err, IsNil)
	err = store.UpdateLocalKeySync(context.TODO(), &localKey2)
	c.Assert(err, IsNil)

	// due to the short sync interval, it is possible that multiple updates
	// have occurred, make the test reliable by succeeding on at lest one
	// update
	c.Assert(expect(func() bool { return localKey1.updated() >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.updated() >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey3.updated() == 0 }), IsNil)

	store.DeleteLocalKey(context.TODO(), &localKey1)
	// localKey1 will be deleted 2 times, one from local key and other from
	// the kvstore watcher
	c.Assert(expect(func() bool { return localKey1.deleted() == 2 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.deleted() == 0 }), IsNil)
	c.Assert(expect(func() bool { return localKey3.deleted() == 0 }), IsNil)

	store.DeleteLocalKey(context.TODO(), &localKey3)
	// localKey3 won't be deleted because it was never added
	c.Assert(expect(func() bool { return localKey3.deleted() == 0 }), IsNil)

	store.DeleteLocalKey(context.TODO(), &localKey2)
	c.Assert(expect(func() bool { return localKey1.deleted() == 2 }), IsNil)
	// localKey2 will be deleted 2 times, one from local key and other from
	// the kvstore watcher
	c.Assert(expect(func() bool { return localKey2.deleted() == 2 }), IsNil)
	c.Assert(expect(func() bool { return localKey3.deleted() == 0 }), IsNil)
}

func (s *StoreSuite) TestStorePeriodicSync(c *C) {
	// Create a store with a very short periodic sync interval
	store, err := JoinSharedStore(Configuration{
		Prefix:                  rand.RandomString(),
		KeyCreator:              newTestType,
		SynchronizationInterval: 10 * time.Millisecond,
		SharedKeyDeleteDelay:    defaults.NodeDeleteDelay,
		Observer:                &observer{},
	})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	defer store.Close(context.TODO())

	localKey1 := initTestType("local1")
	localKey2 := initTestType("local2")

	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	c.Assert(err, IsNil)
	err = store.UpdateLocalKeySync(context.TODO(), &localKey2)
	c.Assert(err, IsNil)

	c.Assert(expect(func() bool { return localKey1.updated() >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.updated() >= 1 }), IsNil)

	store.DeleteLocalKey(context.TODO(), &localKey1)
	store.DeleteLocalKey(context.TODO(), &localKey2)

	c.Assert(expect(func() bool { return localKey1.deleted() == 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.deleted() == 1 }), IsNil)
}

func (s *StoreSuite) TestStoreLocalKeyProtection(c *C) {
	store, err := JoinSharedStore(Configuration{
		Prefix:                  rand.RandomString(),
		KeyCreator:              newTestType,
		SynchronizationInterval: time.Hour, // ensure that periodic sync does not interfer
		Observer:                &observer{},
	})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	defer store.Close(context.TODO())

	localKey1 := initTestType("local1")

	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	c.Assert(err, IsNil)

	c.Assert(expect(func() bool { return localKey1.updated() >= 1 }), IsNil)
	// delete all keys
	kvstore.Client().DeletePrefix(context.TODO(), store.conf.Prefix)
	time.Sleep(10 * time.Millisecond)
	c.Assert(expect(func() bool {
		v, err := kvstore.Client().Get(context.TODO(), store.keyPath(&localKey1))
		return err == nil && v != nil
	}), IsNil)
}

func setupStoreCollaboration(c *C, storePrefix, keyPrefix string) *SharedStore {
	store, err := JoinSharedStore(Configuration{
		Prefix:                  storePrefix,
		KeyCreator:              newTestType,
		SynchronizationInterval: time.Second,
		Observer:                &observer{},
	})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))

	localKey1 := initTestType(keyPrefix + "-local1")
	err = store.UpdateLocalKeySync(context.TODO(), &localKey1)
	c.Assert(err, IsNil)

	localKey2 := initTestType(keyPrefix + "-local2")
	err = store.UpdateLocalKeySync(context.TODO(), &localKey2)
	c.Assert(err, IsNil)

	// wait until local keys was inserted and until the kvstore has confirmed the
	c.Assert(expect(func() bool { return localKey1.updated() >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.updated() >= 1 }), IsNil)

	c.Assert(len(store.getLocalKeys()), Equals, 2)

	return store
}

func (s *StoreSuite) TestStoreCollaboration(c *C) {
	storePrefix := rand.RandomString()

	collab1 := setupStoreCollaboration(c, storePrefix, rand.RandomString())
	defer collab1.Close(context.TODO())

	collab2 := setupStoreCollaboration(c, storePrefix, rand.RandomString())
	defer collab2.Close(context.TODO())

	c.Assert(expect(func() bool {
		totalKeys := len(collab1.getLocalKeys()) + len(collab2.getLocalKeys())
		keys1, keys2 := collab1.getSharedKeys(), collab2.getSharedKeys()

		log.Debugf("totalKeys %d == keys1 %d == keys2 %d", totalKeys, len(keys1), len(keys2))
		return len(keys1) == totalKeys && len(keys1) == len(keys2)
	}), IsNil)
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
