// Copyright 2018-2019 Authors of Cilium
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

// +build privileged_tests

package policymap

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type PolicyMapTestSuite struct{}

var (
	_ = Suite(&PolicyMapTestSuite{})

	testMap = newMap("cilium_policy_test")
)

func runTests(m *testing.M) (int, error) {
	bpf.CheckOrMountFS("")
	if err := bpf.ConfigureResourceLimits(); err != nil {
		return 1, fmt.Errorf("Failed to configure rlimit")
	}

	_ = os.RemoveAll(bpf.MapPath("cilium_policy_test"))
	_, err := testMap.OpenOrCreate()
	if err != nil {
		return 1, fmt.Errorf("Failed to create map")
	}
	defer func() {
		path, _ := testMap.Path()
		os.Remove(path)
	}()
	defer testMap.Close()

	return m.Run(), nil
}

func TestMain(m *testing.M) {
	exitCode, err := runTests(m)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

func (pm *PolicyMapTestSuite) TestPolicyMapDumpToSlice(c *C) {
	c.Assert(testMap, NotNil)

	fooEntry := newKey(1, 1, 1, 1)
	err := testMap.AllowKey(fooEntry, 0)
	c.Assert(err, IsNil)

	dump, err := testMap.DumpToSlice()
	c.Assert(err, IsNil)
	c.Assert(len(dump), Equals, 1)

	// FIXME: It's weird that AllowKey() does the implicit byteorder
	//        conversion above. But not really a bug, so work around it.
	fooEntry = fooEntry.ToNetwork()
	c.Assert(dump[0].Key, checker.DeepEquals, fooEntry)

	// Special case: allow-all entry
	barEntry := newKey(0, 0, 0, 0)
	err = testMap.AllowKey(barEntry, 0)
	c.Assert(err, IsNil)

	dump, err = testMap.DumpToSlice()
	c.Assert(err, IsNil)
	c.Assert(len(dump), Equals, 2)
}

func (pm *PolicyMapTestSuite) TestDeleteNonexistentKey(c *C) {
	key := newKey(27, 80, u8proto.ANY, trafficdirection.Ingress)
	err, errno := testMap.Map.DeleteWithErrno(&key)
	c.Assert(err, Not(IsNil))
	c.Assert(errno, Equals, syscall.ENOENT)
}
