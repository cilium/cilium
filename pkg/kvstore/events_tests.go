// Copyright 2016-2017 Authors of Cilium
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

package kvstore

import (
	"time"

	"github.com/cilium/cilium/pkg/comparator"
	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

type KvstoreSuite struct{}

var _ = Suite(&KvstoreSuite{})

func (s *KvstoreSuite) SetUpTest(c *C) {
	SetupDummy()
}

func expectEvent(c *C, w *Watcher, typ EventType, key string, val []byte) {
	log.WithFields(log.Fields{
		"type":  typ,
		"key":   key,
		"value": string(val),
	}).Debug("Expecting event")

	select {
	case event := <-w.Events:
		c.Assert(event.Typ, Equals, typ)
		c.Assert(event.Key, comparator.DeepEquals, key)

		// etcd does not provide the value of deleted keys
		if backend == "consul" {
			c.Assert(event.Value, comparator.DeepEquals, val)
		}
	case <-time.After(30 * time.Second):
		c.Fatal("timeout while waiting for kvstore watcher event")
	}
}

func (s *KvstoreSuite) TestWatch(c *C) {
	// FIXME GH-1388 Re-enable when fixed
	if backend == Consul {
		c.Skip("consul currently broken (GH-1388)")
	}

	DeleteTree("foo/")
	defer DeleteTree("foo/")

	w := Watch("testWatcher1", "foo/", 100)
	c.Assert(c, Not(IsNil))

	key1, key2 := "foo/key1", "foo/key2"
	val1, val2 := []byte("val1"), []byte("val2")

	err := CreateOnly(key1, val1, false)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeCreate, key1, val1)

	err = Set(key1, val2)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeModify, key1, val2)

	err = CreateOnly(key2, val2, false)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeCreate, key2, val2)

	err = Delete(key1)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key1, val2)

	err = Delete(key2)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key2, val2)

	w.Stop()
}

func (s *KvstoreSuite) TestListAndWatch(c *C) {
	// FIXME GH-1388 Re-enable when fixed
	if backend == Consul {
		c.Skip("consul currently broken (GH-1388)")
	}

	key1, key2 := "foo2/key1", "foo2/key2"
	val1, val2 := []byte("val1"), []byte("val2")

	DeleteTree("foo2/")
	defer DeleteTree("foo2/")

	err := CreateOnly(key1, val1, false)
	c.Assert(err, IsNil)

	w := ListAndWatch("testWatcher2", "foo2/", 100)
	c.Assert(c, Not(IsNil))

	expectEvent(c, w, EventTypeCreate, key1, val1)

	err = CreateOnly(key2, val2, false)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeCreate, key2, val2)

	err = Delete(key1)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key1, val1)

	err = CreateOnly(key1, val1, false)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeCreate, key1, val1)

	err = Delete(key1)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key1, val1)

	err = Delete(key2)
	c.Assert(err, IsNil)
	expectEvent(c, w, EventTypeDelete, key2, val2)

	w.Stop()
}
