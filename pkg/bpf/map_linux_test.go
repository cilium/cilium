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

// +build privileged_tests

package bpf

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type BPFPrivilegedTestSuite struct{}

type TestKey struct {
	Key uint32
}
type TestValue struct {
	Value uint32
}

func (k *TestKey) String() string            { return fmt.Sprintf("key=%d", k.Key) }
func (k *TestKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *TestKey) NewValue() MapValue        { return &TestValue{} }

func (v *TestValue) String() string              { return fmt.Sprintf("value=%d", v.Value) }
func (v *TestValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func DumpParserFunc(key []byte, value []byte) (MapKey, MapValue, error) {
	k, v := TestKey{}, TestValue{}

	if err := ConvertKeyValue(key, value, &k, &v); err != nil {
		return nil, nil, err
	}
	return &k, &v, nil
}

var _ = Suite(&BPFPrivilegedTestSuite{})

var (
	maxEntries = 16

	testMap = NewMap("cilium_test",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		DumpParserFunc).WithCache()
)

func runTests(m *testing.M) (int, error) {
	CheckOrMountFS("")

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

func (s *BPFPrivilegedTestSuite) TestGetMapInfo(c *C) {
	mi, err := GetMapInfo(os.Getpid(), testMap.GetFd())
	c.Assert(err, IsNil)
	c.Assert(&testMap.MapInfo, checker.DeepEquals, mi)
}

func (s *BPFPrivilegedTestSuite) TestOpen(c *C) {
	// Ensure that os.IsNotExist() can be used with Map.Open()
	noSuchMap := NewMap("cilium_test_no_exist",
		MapTypeHash, 4, 4, maxEntries, 0, 0, nil)
	err := noSuchMap.Open()
	c.Assert(os.IsNotExist(err), Equals, true)
	c.Assert(err, ErrorMatches, ".*cilium_test_no_exist.*")

	// existingMap is the same as testMap. Opening should succeed.
	existingMap := NewMap("cilium_test",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		DumpParserFunc).WithCache()
	err = existingMap.Open()
	c.Check(err, IsNil)      // Avoid assert to ensure Close() is called below.
	err = existingMap.Open() // Reopen should be no-op.
	c.Check(err, IsNil)
	err = existingMap.Close()
	c.Assert(err, IsNil)
}

func (s *BPFPrivilegedTestSuite) TestOpenMap(c *C) {
	openedMap, err := OpenMap("cilium_test_no_exist")
	c.Assert(err, Not(IsNil))
	c.Assert(openedMap, IsNil)

	openedMap, err = OpenMap("cilium_test")
	noDiff := openedMap.DeepEquals(testMap)
	c.Assert(noDiff, Equals, true)
	c.Assert(err, IsNil)
}

func (s *BPFPrivilegedTestSuite) TestOpenOrCreate(c *C) {
	// existingMap is the same as testMap. OpenOrCreate should skip recreation.
	existingMap := NewMap("cilium_test",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		DumpParserFunc).WithCache()
	isNew, err := existingMap.OpenOrCreate()
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	// preallocMap unsets BPF_F_NO_PREALLOC. OpenOrCreate should recreate map.
	EnableMapPreAllocation() // prealloc on/off is controllable in HASH map case.
	preallocMap := NewMap("cilium_test",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		0,
		0,
		DumpParserFunc).WithCache()
	isNew, err = preallocMap.OpenOrCreate()
	defer preallocMap.Close()
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)
	DisableMapPreAllocation()

	// preallocMap is already open. OpenOrCreate does nothing.
	isNew, err = preallocMap.OpenOrCreate()
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)
}

func (s *BPFPrivilegedTestSuite) TestOpenParallel(c *C) {
	parallelMap := NewMap("cilium_test",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		DumpParserFunc).WithCache()
	isNew, err := parallelMap.OpenParallel()
	defer parallelMap.Close()
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)

	isNew, err = parallelMap.OpenParallel()
	c.Assert(isNew, Equals, false)
	c.Assert(err, Not(IsNil))

	noDiff := parallelMap.DeepEquals(testMap)
	c.Assert(noDiff, Equals, true)

	key1 := &TestKey{Key: 101}
	value1 := &TestValue{Value: 201}
	key2 := &TestKey{Key: 102}
	value2 := &TestValue{Value: 202}

	err = testMap.Update(key1, value1)
	c.Assert(err, IsNil)
	err = parallelMap.Update(key2, value2)
	c.Assert(err, IsNil)

	value, err := testMap.Lookup(key1)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value1)
	value, err = testMap.Lookup(key2)
	c.Assert(err, Not(IsNil))
	c.Assert(value, IsNil)

	value, err = parallelMap.Lookup(key1)
	c.Assert(err, Not(IsNil))
	c.Assert(value, IsNil)
	value, err = parallelMap.Lookup(key2)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value2)

	parallelMap.EndParallelMode()
}

func (s *BPFPrivilegedTestSuite) TestBasicManipulation(c *C) {
	// existingMap is the same as testMap. Opening should succeed.
	existingMap := NewMap("cilium_test",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		DumpParserFunc).WithCache()
	err := existingMap.Open()
	defer existingMap.Close()
	c.Assert(err, IsNil)

	key1 := &TestKey{Key: 103}
	value1 := &TestValue{Value: 203}
	key2 := &TestKey{Key: 104}
	value2 := &TestValue{Value: 204}

	err = existingMap.Update(key1, value1)
	c.Assert(err, IsNil)
	// key    val
	// 103    203
	value, err := existingMap.Lookup(key1)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value1)
	value, err = existingMap.Lookup(key2)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)

	err = existingMap.Update(key1, value2)
	c.Assert(err, IsNil)
	// key    val
	// 103    204
	value, err = existingMap.Lookup(key1)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value2)

	err = existingMap.Update(key2, value2)
	c.Assert(err, IsNil)
	// key    val
	// 103    204
	// 104    204
	value, err = existingMap.Lookup(key1)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value2)
	value, err = existingMap.Lookup(key2)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value2)

	err = existingMap.Delete(key1)
	c.Assert(err, IsNil)
	// key    val
	// 104    204
	value, err = existingMap.Lookup(key1)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)

	err = existingMap.DeleteAll()
	c.Assert(err, IsNil)
	value, err = existingMap.Lookup(key1)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)
	err = existingMap.DeleteAll()
	c.Assert(err, IsNil)
}

func (s *BPFPrivilegedTestSuite) TestDump(c *C) {
	key1 := &TestKey{Key: 105}
	value1 := &TestValue{Value: 205}
	key2 := &TestKey{Key: 106}
	value2 := &TestValue{Value: 206}

	err := testMap.Update(key1, value1)
	c.Assert(err, IsNil)
	err = testMap.Update(key2, value1)
	c.Assert(err, IsNil)
	err = testMap.Update(key2, value2)
	c.Assert(err, IsNil)

	dump1 := map[string][]string{}
	testMap.Dump(dump1)
	c.Assert(dump1, checker.DeepEquals, map[string][]string{
		"key=105": {"value=205"},
		"key=106": {"value=206"},
	})

	dump2 := map[string][]string{}
	customCb := func(key MapKey, value MapValue) {
		dump2[key.String()] = append(dump2[key.String()], "custom-"+value.String())
	}
	testMap.DumpWithCallback(customCb)
	c.Assert(dump2, checker.DeepEquals, map[string][]string{
		"key=105": {"custom-value=205"},
		"key=106": {"custom-value=206"},
	})

	dump3 := map[string][]string{}
	noSuchMap := NewMap("cilium_test_no_exist",
		MapTypeHash, 4, 4, maxEntries, 0, 0, nil)
	err = noSuchMap.DumpIfExists(dump3)
	c.Assert(err, IsNil)
	c.Assert(len(dump3), Equals, 0)

	dump2 = map[string][]string{}
	err = noSuchMap.DumpWithCallbackIfExists(customCb)
	c.Assert(err, IsNil)
	c.Assert(len(dump2), Equals, 0)
}

func (s *BPFPrivilegedTestSuite) TestGetModel(c *C) {
	model := testMap.GetModel()
	c.Assert(model, Not(IsNil))
}

func (s *BPFPrivilegedTestSuite) TestCheckAndUpgrade(c *C) {
	// CheckAndUpgrade removes map file if upgrade is needed
	// so we setup and use another map.
	upgradeMap := NewMap("cilium_test_upgrade",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		DumpParserFunc).WithCache()
	_, err := upgradeMap.OpenOrCreate()
	c.Assert(err, IsNil)
	defer func() {
		path, _ := upgradeMap.Path()
		os.Remove(path)
	}()
	defer upgradeMap.Close()

	// Exactly the same MapInfo so it won't be upgraded.
	upgrade := upgradeMap.CheckAndUpgrade(&upgradeMap.MapInfo)
	c.Assert(upgrade, Equals, false)

	// preallocMap unsets BPF_F_NO_PREALLOC so upgrade is needed.
	EnableMapPreAllocation()
	preallocMap := NewMap("cilium_test_upgrade",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		0,
		0,
		DumpParserFunc).WithCache()
	upgrade = upgradeMap.CheckAndUpgrade(&preallocMap.MapInfo)
	c.Assert(upgrade, Equals, true)
	DisableMapPreAllocation()
}

func (s *BPFPrivilegedTestSuite) TestUnpin(c *C) {
	var exist bool
	unpinMap := NewMap("cilium_test_unpin",
		MapTypeHash,
		int(unsafe.Sizeof(TestKey{})),
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		DumpParserFunc).WithCache()
	_, err := unpinMap.OpenOrCreate()
	c.Assert(err, IsNil)
	exist, err = unpinMap.exist()
	c.Assert(err, IsNil)
	c.Assert(exist, Equals, true)

	err = unpinMap.Unpin()
	c.Assert(err, IsNil)
	exist, err = unpinMap.exist()
	c.Assert(err, IsNil)
	c.Assert(exist, Equals, false)

	err = unpinMap.UnpinIfExists()
	c.Assert(err, IsNil)
	exist, err = unpinMap.exist()
	c.Assert(err, IsNil)
	c.Assert(exist, Equals, false)
}
