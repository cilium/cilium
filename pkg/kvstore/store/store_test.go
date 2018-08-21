// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

const (
	testPrefix = "store-tests"
)

func Test(t *testing.T) {
	TestingT(t)
}

type StoreSuite struct{}

type StoreEtcdSuite struct {
	StoreSuite
}

var _ = Suite(&StoreEtcdSuite{})

func (e *StoreEtcdSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("etcd")
}

func (e *StoreEtcdSuite) TearDownTest(c *C) {
	kvstore.DeletePrefix(testPrefix)
	kvstore.Close()
}

type StoreConsulSuite struct {
	StoreSuite
}

var _ = Suite(&StoreConsulSuite{})

func (e *StoreConsulSuite) SetUpTest(c *C) {
	kvstore.SetupDummy("consul")
}

func (e *StoreConsulSuite) TearDownTest(c *C) {
	kvstore.DeletePrefix(testPrefix)
	kvstore.Close()
}

type TestType struct {
	Name string

	updated int
	deleted int
}

var testType = TestType{}

func (t *TestType) OnUpdate()                   { t.updated++ }
func (t *TestType) OnDelete()                   { t.deleted++ }
func (t *TestType) GetKeyName() string          { return t.Name }
func (t *TestType) Marshal() ([]byte, error)    { return json.Marshal(t) }
func (t *TestType) Unmarshal(data []byte) error { return json.Unmarshal(data, t) }

func newTestType() Key {
	t := TestType{}
	return &t
}

func (s *StoreSuite) TestStoreCreation(c *C) {
	// Missing Prefix must result in error
	store, err := JoinSharedStore(Configuration{})
	c.Assert(err, ErrorMatches, "Prefix must be specified")
	c.Assert(store, IsNil)

	// Missing KeyCreator must result in error
	store, err = JoinSharedStore(Configuration{Prefix: testutils.RandomRune()})
	c.Assert(err, ErrorMatches, "KeyCreator must be specified")
	c.Assert(store, IsNil)

	// Basic creation should result in default values
	store, err = JoinSharedStore(Configuration{Prefix: testutils.RandomRune(), KeyCreator: newTestType})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	c.Assert(store.conf.SynchronizationInterval, Equals, synchronizationIntervalDefault)
	store.Close()
}

func expect(check func() bool) error {
	start := time.Now()
	for {
		if check() {
			return nil
		}

		if time.Since(start) > 10*time.Second {
			return fmt.Errorf("timeout while waiting for expected value")
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (s *StoreSuite) TestStoreOperations(c *C) {
	// Basic creation should result in default values
	store, err := JoinSharedStore(Configuration{Prefix: testutils.RandomRune(), KeyCreator: newTestType})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	defer store.Close()

	localKey1 := TestType{Name: "local1"}
	localKey2 := TestType{Name: "local2"}
	localKey3 := TestType{Name: "local3"}

	err = store.UpdateLocalKeySync(&localKey1)
	c.Assert(err, IsNil)
	err = store.UpdateLocalKeySync(&localKey2)
	c.Assert(err, IsNil)

	// due to the short sync interval, it is possible that multiple updates
	// have occurred, make the test reliable by succeeding on at lest one
	// update
	c.Assert(expect(func() bool { return localKey1.updated >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.updated >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey3.updated == 0 }), IsNil)

	store.DeleteLocalKey(&localKey1)
	c.Assert(expect(func() bool { return localKey1.deleted >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.deleted == 0 }), IsNil)
	c.Assert(expect(func() bool { return localKey3.deleted == 0 }), IsNil)

	store.DeleteLocalKey(&localKey3)
	c.Assert(expect(func() bool { return localKey3.deleted == 0 }), IsNil)

	store.DeleteLocalKey(&localKey2)
	c.Assert(expect(func() bool { return localKey1.deleted == 2 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.deleted == 2 }), IsNil)
	c.Assert(expect(func() bool { return localKey3.deleted == 0 }), IsNil)
}

func (s *StoreSuite) TestStorePeriodicSync(c *C) {
	// Create a store with a very short periodic sync interval
	store, err := JoinSharedStore(Configuration{
		Prefix:                  testutils.RandomRune(),
		KeyCreator:              newTestType,
		SynchronizationInterval: 10 * time.Millisecond,
	})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))
	defer store.Close()

	localKey1 := TestType{Name: "local1"}
	localKey2 := TestType{Name: "local2"}

	err = store.UpdateLocalKeySync(&localKey1)
	c.Assert(err, IsNil)
	err = store.UpdateLocalKeySync(&localKey2)
	c.Assert(err, IsNil)

	// the sync interval occurs every 10 millisecond, wait until 3 updates
	// have occurred
	c.Assert(expect(func() bool { return localKey1.updated >= 3 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.updated >= 3 }), IsNil)

	store.DeleteLocalKey(&localKey1)
	store.DeleteLocalKey(&localKey2)

	c.Assert(expect(func() bool { return localKey1.deleted >= 1 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.deleted >= 1 }), IsNil)
}

func setupStoreCollaboration(c *C, storePrefix, keyPrefix string) *SharedStore {
	store, err := JoinSharedStore(Configuration{
		Prefix:                  storePrefix,
		KeyCreator:              newTestType,
		SynchronizationInterval: time.Second,
	})
	c.Assert(err, IsNil)
	c.Assert(store, Not(IsNil))

	localKey1 := TestType{Name: keyPrefix + "-local1"}
	localKey2 := TestType{Name: keyPrefix + "-local2"}

	err = store.UpdateLocalKeySync(&localKey1)
	c.Assert(err, IsNil)
	err = store.UpdateLocalKeySync(&localKey2)
	c.Assert(err, IsNil)

	// wait until local keys was inserted and until the kvstore has confirmed the
	c.Assert(expect(func() bool { return localKey1.updated == 2 }), IsNil)
	c.Assert(expect(func() bool { return localKey2.updated == 2 }), IsNil)

	c.Assert(len(store.getLocalKeys()), Equals, 2)

	return store
}

func (s *StoreSuite) TestStoreCollaboration(c *C) {
	storePrefix := testutils.RandomRune()

	collab1 := setupStoreCollaboration(c, storePrefix, testutils.RandomRune())
	defer collab1.Close()

	collab2 := setupStoreCollaboration(c, storePrefix, testutils.RandomRune())
	defer collab2.Close()

	c.Assert(expect(func() bool {
		totalKeys := len(collab1.getLocalKeys()) + len(collab2.getLocalKeys())
		keys1, keys2 := collab1.getSharedKeys(), collab2.getSharedKeys()

		log.Debugf("totalKeys %d == keys1 %d == keys2 %d", totalKeys, len(keys1), len(keys2))
		return len(keys1) == totalKeys && len(keys1) == len(keys2)
	}), IsNil)
}
