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

package clustermesh

import (
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/cilium/cilium/pkg/testutils"

	. "gopkg.in/check.v1"
)

func createFile(c *C, name string) {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE, 0666)
	c.Assert(err, IsNil)
	f.Sync()
	f.Close()
}

func expectExists(c *C, rc *RemoteClustersCache, name string) {
	c.Assert(rc.clusters[name], Not(IsNil))
}

func expectChange(c *C, rc *RemoteClustersCache, name string) {
	cluster := rc.clusters[name]
	c.Assert(cluster, Not(IsNil))

	select {
	case <-cluster.changed:
	case <-time.After(time.Second):
		c.Fatal("timeout while waiting for changed event")
	}
}

func expectNotExist(c *C, rc *RemoteClustersCache, name string) {
	c.Assert(rc.clusters[name], IsNil)
}

func (s *ClusterMeshTestSuite) TestWatchConfigDirectory(c *C) {
	skipKvstoreConnection = true

	dir, err := ioutil.TempDir("", "multicluster")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	file1 := path.Join(dir, "cluster1")
	file2 := path.Join(dir, "cluster2")
	file3 := path.Join(dir, "cluster3")

	createFile(c, file1)
	createFile(c, file2)

	rc, err := NewRemoteClustersCache("test1", dir, testNodeCreator)
	c.Assert(err, IsNil)
	c.Assert(rc, Not(IsNil))
	defer rc.Close()

	c.Assert(testutils.WaitUntil(func() bool { return len(rc.clusters) == 2 }, time.Second), IsNil)
	expectExists(c, rc, "cluster1")
	expectExists(c, rc, "cluster2")
	expectNotExist(c, rc, "cluster3")

	err = os.RemoveAll(file1)
	c.Assert(err, IsNil)
	createFile(c, file3)

	c.Assert(testutils.WaitUntil(func() bool { return len(rc.clusters) == 2 }, time.Second), IsNil)
	expectNotExist(c, rc, "cluster1")
	expectExists(c, rc, "cluster2")
	expectExists(c, rc, "cluster3")

	err = os.Rename(file3, file1)
	c.Assert(err, IsNil)

	c.Assert(testutils.WaitUntil(func() bool { return rc.clusters["cluster1"] != nil }, time.Second), IsNil)
	expectExists(c, rc, "cluster2")
	expectNotExist(c, rc, "cluster3")

	err = os.Chtimes(file1, time.Now(), time.Now())
	c.Assert(err, IsNil)

	// give time for events to be processed
	time.Sleep(100 * time.Millisecond)
	expectChange(c, rc, "cluster1")

	err = os.RemoveAll(file1)
	c.Assert(err, IsNil)
	err = os.RemoveAll(file2)
	c.Assert(err, IsNil)

	c.Assert(testutils.WaitUntil(func() bool { return len(rc.clusters) == 0 }, time.Second), IsNil)
	expectNotExist(c, rc, "cluster1")
	expectNotExist(c, rc, "cluster2")
	expectNotExist(c, rc, "cluster3")

}
