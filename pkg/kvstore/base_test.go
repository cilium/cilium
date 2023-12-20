// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"fmt"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

// BaseTests is the struct that needs to be embedded into all test suite
// structs of backend implementations. It contains all test functions that are
// agnostic to the backend implementation.
type BaseTests struct{}

func (s *BaseTests) TestLock(c *C) {
	prefix := "locktest/"

	Client().DeletePrefix(context.TODO(), prefix)
	defer Client().DeletePrefix(context.TODO(), prefix)

	for i := 0; i < 10; i++ {
		lock, err := LockPath(context.Background(), Client(), fmt.Sprintf("%sfoo/%d", prefix, i))
		c.Assert(err, IsNil)
		c.Assert(lock, Not(IsNil))
		lock.Unlock(context.TODO())
	}
}

func testKey(prefix string, i int) string {
	return fmt.Sprintf("%s%s/%010d", prefix, "foo", i)
}

func testValue(i int) string {
	return fmt.Sprintf("blah %d blah %d", i, i)
}

func (s *BaseTests) TestGetSet(c *C) {
	prefix := "unit-test/"
	maxID := 8

	Client().DeletePrefix(context.TODO(), prefix)
	defer Client().DeletePrefix(context.TODO(), prefix)

	pairs, err := Client().ListPrefix(context.Background(), prefix)
	c.Assert(err, IsNil)
	c.Assert(pairs, HasLen, 0)

	for i := 0; i < maxID; i++ {
		val, err := Client().Get(context.TODO(), testKey(prefix, i))
		c.Assert(err, IsNil)
		c.Assert(val, IsNil)

		c.Assert(Client().Update(context.TODO(), testKey(prefix, i), []byte(testValue(i)), false), IsNil)

		val, err = Client().Get(context.TODO(), testKey(prefix, i))
		c.Assert(err, IsNil)
		c.Assert(string(val), checker.DeepEquals, testValue(i))
	}

	pairs, err = Client().ListPrefix(context.Background(), prefix)
	c.Assert(err, IsNil)
	c.Assert(pairs, HasLen, maxID)

	for i := 0; i < maxID; i++ {
		c.Assert(Client().Delete(context.TODO(), testKey(prefix, i)), IsNil)

		val, err := Client().Get(context.TODO(), testKey(prefix, i))
		c.Assert(err, IsNil)
		c.Assert(val, IsNil)
	}

	pairs, err = Client().ListPrefix(context.Background(), prefix)
	c.Assert(err, IsNil)
	c.Assert(pairs, HasLen, 0)
}

func (s *BaseTests) BenchmarkGet(c *C) {
	prefix := "unit-test/"
	Client().DeletePrefix(context.TODO(), prefix)
	defer Client().DeletePrefix(context.TODO(), prefix)

	key := testKey(prefix, 1)
	c.Assert(Client().Update(context.TODO(), key, []byte(testValue(100)), false), IsNil)

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		Client().Get(context.TODO(), key)
	}
}

func (s *BaseTests) BenchmarkSet(c *C) {
	prefix := "unit-test/"
	Client().DeletePrefix(context.TODO(), prefix)
	defer Client().DeletePrefix(context.TODO(), prefix)

	key, val := testKey(prefix, 1), testValue(100)
	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		Client().Update(context.TODO(), key, []byte(val), false)
	}
}

func (s *BaseTests) TestUpdate(c *C) {
	prefix := "unit-test/"

	Client().DeletePrefix(context.TODO(), prefix)
	defer Client().DeletePrefix(context.TODO(), prefix)

	// create
	c.Assert(Client().Update(context.Background(), testKey(prefix, 0), []byte(testValue(0)), true), IsNil)

	val, err := Client().Get(context.TODO(), testKey(prefix, 0))
	c.Assert(err, IsNil)
	c.Assert(string(val), checker.DeepEquals, testValue(0))

	// update
	c.Assert(Client().Update(context.Background(), testKey(prefix, 0), []byte(testValue(0)), true), IsNil)

	val, err = Client().Get(context.TODO(), testKey(prefix, 0))
	c.Assert(err, IsNil)
	c.Assert(string(val), checker.DeepEquals, testValue(0))
}

func (s *BaseTests) TestCreateOnly(c *C) {
	prefix := "unit-test/"

	Client().DeletePrefix(context.TODO(), prefix)
	defer Client().DeletePrefix(context.TODO(), prefix)

	success, err := Client().CreateOnly(context.Background(), testKey(prefix, 0), []byte(testValue(0)), false)
	c.Assert(err, IsNil)
	c.Assert(success, Equals, true)

	val, err := Client().Get(context.TODO(), testKey(prefix, 0))
	c.Assert(err, IsNil)
	c.Assert(string(val), checker.DeepEquals, testValue(0))

	success, err = Client().CreateOnly(context.Background(), testKey(prefix, 0), []byte(testValue(1)), false)
	c.Assert(err, IsNil)
	c.Assert(success, Equals, false)

	val, err = Client().Get(context.TODO(), testKey(prefix, 0))
	c.Assert(err, IsNil)
	c.Assert(string(val), checker.DeepEquals, testValue(0))
}

func expectEvent(c *C, w *Watcher, typ EventType, key string, val string) {
	select {
	case event := <-w.Events:
		c.Assert(event.Typ, Equals, typ)

		if event.Typ != EventTypeListDone {
			c.Assert(event.Key, checker.DeepEquals, key)

			// etcd does not provide the value of deleted keys
			if selectedModule == "consul" {
				c.Assert(event.Value, checker.DeepEquals, val)
			}
		}
	case <-time.After(10 * time.Second):
		c.Fatal("timeout while waiting for kvstore watcher event")
	}
}

func (s *BaseTests) TestListAndWatch(c *C) {
	key1, key2 := "foo2/key1", "foo2/key2"
	val1, val2 := "val1", "val2"

	Client().DeletePrefix(context.TODO(), "foo2/")
	defer Client().DeletePrefix(context.TODO(), "foo2/")

	success, err := Client().CreateOnly(context.Background(), key1, []byte(val1), false)
	c.Assert(err, IsNil)
	c.Assert(success, Equals, true)

	w := Client().ListAndWatch(context.TODO(), "foo2/", 100)
	c.Assert(c, Not(IsNil))

	expectEvent(c, w, EventTypeCreate, key1, val1)
	expectEvent(c, w, EventTypeListDone, "", "")

	success, err = Client().CreateOnly(context.Background(), key2, []byte(val2), false)
	c.Assert(err, IsNil)
	c.Assert(success, Equals, true)
	expectEvent(c, w, EventTypeCreate, key2, val2)

	err = Client().Delete(context.TODO(), key1)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key1, val1)

	success, err = Client().CreateOnly(context.Background(), key1, []byte(val1), false)
	c.Assert(err, IsNil)
	c.Assert(success, Equals, true)
	expectEvent(c, w, EventTypeCreate, key1, val1)

	err = Client().Delete(context.TODO(), key1)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key1, val1)

	err = Client().Delete(context.TODO(), key2)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key2, val2)

	w.Stop()
}
