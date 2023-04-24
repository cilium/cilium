// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/ebpf/rlimit"
)

var testMap = newMap("cilium_policy_test")

type PolicyMapPrivilegedTestSuite struct {
	teardown func() error
}

var _ = Suite(&PolicyMapPrivilegedTestSuite{})

func (pm *PolicyMapPrivilegedTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedCheck(c)

	bpf.CheckOrMountFS("")

	if err := rlimit.RemoveMemlock(); err != nil {
		c.Fatal(err)
	}

	_ = os.RemoveAll(bpf.MapPath("cilium_policy_test"))
	_, err := testMap.OpenOrCreate()
	if err != nil {
		c.Fatal("Failed to create map:", err)
	}

	pm.teardown = func() error {
		testMap.Close()

		path, err := testMap.Path()
		if err != nil {
			return err
		}

		return os.Remove(path)
	}
}

func (pm *PolicyMapPrivilegedTestSuite) TearDownSuite(c *C) {
	if pm.teardown != nil {
		if err := pm.teardown(); err != nil {
			c.Fatal(err)
		}
	}
}

func (pm *PolicyMapPrivilegedTestSuite) TearDownTest(c *C) {
	testMap.DeleteAll()
}

func (pm *PolicyMapPrivilegedTestSuite) TestPolicyMapDumpToSlice(c *C) {
	c.Assert(testMap, NotNil)

	fooEntry := newKey(1, 1, 1, 1)
	err := testMap.AllowKey(fooEntry, 0, 0)
	c.Assert(err, IsNil)

	dump, err := testMap.DumpToSlice()
	c.Assert(err, IsNil)
	c.Assert(len(dump), Equals, 1)

	c.Assert(dump[0].Key, checker.DeepEquals, fooEntry)

	// Special case: allow-all entry
	barEntry := newKey(0, 0, 0, 0)
	err = testMap.AllowKey(barEntry, 0, 0)
	c.Assert(err, IsNil)

	dump, err = testMap.DumpToSlice()
	c.Assert(err, IsNil)
	c.Assert(len(dump), Equals, 2)
}

func (pm *PolicyMapPrivilegedTestSuite) TestDeleteNonexistentKey(c *C) {
	key := newKey(27, 80, u8proto.ANY, trafficdirection.Ingress)
	err := testMap.Map.Delete(&key)
	c.Assert(err, Not(IsNil))
	var errno unix.Errno
	c.Assert(errors.As(err, &errno), Equals, true)
	c.Assert(errno, Equals, unix.ENOENT)
}

func (pm *PolicyMapPrivilegedTestSuite) TestDenyPolicyMapDumpToSlice(c *C) {
	c.Assert(testMap, NotNil)

	fooEntry := newKey(1, 1, 1, 1)
	fooValue := newEntry(0, 0, getPolicyEntryFlags(policyEntryFlagParams{IsDeny: true}))
	err := testMap.DenyKey(fooEntry)
	c.Assert(err, IsNil)

	dump, err := testMap.DumpToSlice()
	c.Assert(err, IsNil)
	c.Assert(len(dump), Equals, 1)

	c.Assert(dump[0].Key, checker.DeepEquals, fooEntry)
	c.Assert(dump[0].PolicyEntry, checker.DeepEquals, fooValue)

	// Special case: deny-all entry
	barEntry := newKey(0, 0, 0, 0)
	err = testMap.DenyKey(barEntry)
	c.Assert(err, IsNil)

	dump, err = testMap.DumpToSlice()
	c.Assert(err, IsNil)
	c.Assert(len(dump), Equals, 2)
}
