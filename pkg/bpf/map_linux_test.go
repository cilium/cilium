// Copyright 2018-2021 Authors of Cilium
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"

	. "gopkg.in/check.v1"
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
func (k *TestKey) DeepCopyMapKey() MapKey    { return &TestKey{k.Key} }

func (v *TestValue) String() string              { return fmt.Sprintf("value=%d", v.Value) }
func (v *TestValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *TestValue) DeepCopyMapValue() MapValue  { return &TestValue{v.Value} }

var _ = Suite(&BPFPrivilegedTestSuite{})

var (
	maxEntries = 16

	testMap = NewMap("cilium_test",
		MapTypeHash,
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue,
	).WithCache()
)

func runTests(m *testing.M) (int, error) {
	CheckOrMountFS("")
	if err := ConfigureResourceLimits(); err != nil {
		return 1, fmt.Errorf("Failed to configure rlimit")
	}

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

	// Check OpenMap warning section
	testMap.MapKey = nil
	testMap.MapValue = nil
	defer func() {
		testMap.MapKey = &TestKey{}
		testMap.MapValue = &TestValue{}
	}()
	c.Assert(&testMap.MapInfo, checker.DeepEquals, mi)
}

func (s *BPFPrivilegedTestSuite) TestOpen(c *C) {
	// Ensure that os.IsNotExist() can be used with Map.Open()
	noSuchMap := NewMap("cilium_test_no_exist",
		MapTypeHash, &TestKey{}, 4, &TestValue{}, 4, maxEntries, 0, 0, nil)
	err := noSuchMap.Open()
	c.Assert(os.IsNotExist(err), Equals, true)
	c.Assert(err, ErrorMatches, ".*cilium_test_no_exist.*")

	// existingMap is the same as testMap. Opening should succeed.
	existingMap := NewMap("cilium_test",
		MapTypeHash,
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue).WithCache()
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
	c.Assert(err, IsNil)

	// Check OpenMap warning section
	testMap.MapKey = nil
	testMap.MapValue = nil
	defer func() {
		testMap.MapKey = &TestKey{}
		testMap.MapValue = &TestValue{}
	}()
	noDiff := openedMap.DeepEquals(testMap)
	c.Assert(noDiff, Equals, true)
}

func (s *BPFPrivilegedTestSuite) TestOpenOrCreate(c *C) {
	// existingMap is the same as testMap. OpenOrCreate should skip recreation.
	existingMap := NewMap("cilium_test",
		MapTypeHash,
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue).WithCache()
	isNew, err := existingMap.OpenOrCreate()
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, false)

	// preallocMap unsets BPF_F_NO_PREALLOC. OpenOrCreate should recreate map.
	EnableMapPreAllocation() // prealloc on/off is controllable in HASH map case.
	preallocMap := NewMap("cilium_test",
		MapTypeHash,
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		0,
		0,
		ConvertKeyValue).WithCache()
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
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue).WithCache()
	isNew, err := parallelMap.OpenParallel()
	defer parallelMap.Close()
	c.Assert(err, IsNil)
	c.Assert(isNew, Equals, true)

	isNew, err = parallelMap.OpenParallel()
	c.Assert(isNew, Equals, false)
	c.Assert(err, Not(IsNil))

	// Check OpenMap warning section
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
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue).WithCache()
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

	err = existingMap.Delete(key1)
	c.Assert(err, Not(IsNil))

	deleted, err := existingMap.SilentDelete(key1)
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, false)

	err = existingMap.Update(key1, value1)
	c.Assert(err, IsNil)

	deleted, err = existingMap.SilentDelete(key1)
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, true)

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
		MapTypeHash, &TestKey{}, 4, &TestValue{}, 4, maxEntries, 0, 0, nil)
	err = noSuchMap.DumpIfExists(dump3)
	c.Assert(err, IsNil)
	c.Assert(len(dump3), Equals, 0)

	dump2 = map[string][]string{}
	err = noSuchMap.DumpWithCallbackIfExists(customCb)
	c.Assert(err, IsNil)
	c.Assert(len(dump2), Equals, 0)

	// Validate that if the key is zero, it shows up in dump output.
	keyZero := &TestKey{Key: 0}
	valueZero := &TestValue{Value: 0}
	err = testMap.Update(keyZero, valueZero)
	c.Assert(err, IsNil)

	dump4 := map[string][]string{}
	customCb = func(key MapKey, value MapValue) {
		dump4[key.String()] = append(dump4[key.String()], "custom-"+value.String())
	}
	ds := NewDumpStats(testMap)
	err = testMap.DumpReliablyWithCallback(customCb, ds)
	c.Assert(err, IsNil)
	c.Assert(dump4, checker.DeepEquals, map[string][]string{
		"key=0":   {"custom-value=0"},
		"key=105": {"custom-value=205"},
		"key=106": {"custom-value=206"},
	})

	dump5 := map[string][]string{}
	err = testMap.Dump(dump5)
	c.Assert(err, IsNil)
	c.Assert(dump5, checker.DeepEquals, map[string][]string{
		"key=0":   {"value=0"},
		"key=105": {"value=205"},
		"key=106": {"value=206"},
	})
}

func (s *BPFPrivilegedTestSuite) TestDumpReliablyWithCallback(c *C) {
	maxEntries := uint32(256)
	m := NewMap("cilium_dump_test",
		MapTypeHash,
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		int(maxEntries),
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue,
	).WithCache()
	_, err := m.OpenOrCreate()
	c.Assert(err, IsNil)
	defer func() {
		path, _ := m.Path()
		os.Remove(path)
	}()
	defer m.Close()

	for i := uint32(4); i < maxEntries; i++ {
		err := m.Update(&TestKey{Key: i}, &TestValue{Value: i + 100})
		c.Check(err, IsNil) // we want to run the deferred calls
	}
	// start a goroutine that continuously updates the map
	started := make(chan struct{}, 1)
	done := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		started <- struct{}{}
		for {
			for i := uint32(0); i < 4; i++ {
				if i < 3 {
					err := m.Update(&TestKey{Key: i}, &TestValue{Value: i + 100})
					// avoid assert to ensure we call wg.Done
					c.Check(err, IsNil)
				}
				if i > 0 {
					err := m.Delete(&TestKey{Key: i - 1})
					// avoid assert to ensure we call wg.Done
					c.Check(err, IsNil)
				}
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	<-started // wait until the routine has started to start the actual tests
	wg.Add(1)
	go func() {
		defer wg.Done()
		expect := map[string]string{}
		for i := uint32(4); i < maxEntries; i++ {
			expect[fmt.Sprintf("key=%d", i)] = fmt.Sprintf("custom-value=%d", i+100)
		}
		for i := 0; i < 100; i++ {
			dump := map[string]string{}
			customCb := func(key MapKey, value MapValue) {
				k, err := strconv.ParseUint(strings.TrimPrefix(key.String(), "key="), 10, 32)
				c.Check(err, IsNil)
				if uint32(k) >= 4 {
					dump[key.String()] = "custom-" + value.String()
				}
			}
			ds := NewDumpStats(m)
			if i == 0 {
				// artificially trigger MaxLookupError as max lookup is based
				// on ds.MaxEntries
				ds.MaxEntries = 1
			}
			if err := m.DumpReliablyWithCallback(customCb, ds); err != nil {
				// avoid Assert to ensure the done signal is sent
				c.Check(err, Equals, ErrMaxLookup)
			} else {
				// avoid Assert to ensure the done signal is sent
				c.Check(dump, checker.DeepEquals, expect)
			}
		}
		done <- struct{}{}
	}()
	wg.Wait()
}

func (s *BPFPrivilegedTestSuite) TestDeleteAll(c *C) {
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

	keyZero := &TestKey{Key: 0}
	valueZero := &TestValue{Value: 0}
	err = testMap.Update(keyZero, valueZero)
	c.Assert(err, IsNil)

	dump1 := map[string][]string{}
	err = testMap.Dump(dump1)
	c.Assert(err, IsNil)
	c.Assert(dump1, checker.DeepEquals, map[string][]string{
		"key=0":   {"value=0"},
		"key=105": {"value=205"},
		"key=106": {"value=206"},
	})

	err = testMap.DeleteAll()
	c.Assert(err, IsNil)

	dump2 := map[string][]string{}
	err = testMap.Dump(dump2)
	c.Assert(err, IsNil)
}

func (s *BPFPrivilegedTestSuite) TestGetModel(c *C) {
	model := testMap.GetModel()
	c.Assert(model, Not(IsNil))
}

func (s *BPFPrivilegedTestSuite) TestCheckAndUpgrade(c *C) {
	tests := []struct {
		name    string
		run     func() []*Map
		postRun func(maps ...*Map)
	}{
		{
			name: "MapTypeHash: no prealloc to prealloc upgrade",
			run: func() []*Map {
				// CheckAndUpgrade removes map file if upgrade is needed
				// so we setup and use another map.
				upgradeMap := NewMap("cilium_test_upgrade",
					MapTypeHash,
					&TestKey{},
					int(unsafe.Sizeof(TestKey{})),
					&TestValue{},
					int(unsafe.Sizeof(TestValue{})),
					maxEntries,
					BPF_F_NO_PREALLOC,
					0,
					ConvertKeyValue).WithCache()
				_, err := upgradeMap.OpenOrCreate()
				c.Assert(err, IsNil)

				// Exactly the same MapInfo so it won't be upgraded.
				upgrade := upgradeMap.CheckAndUpgrade(&upgradeMap.MapInfo)
				c.Assert(upgrade, Equals, false)

				// preallocMap unsets BPF_F_NO_PREALLOC so upgrade is needed.
				EnableMapPreAllocation()
				preallocMap := NewMap("cilium_test_upgrade",
					MapTypeHash,
					&TestKey{},
					int(unsafe.Sizeof(TestKey{})),
					&TestValue{},
					int(unsafe.Sizeof(TestValue{})),
					maxEntries,
					0,
					0,
					ConvertKeyValue).WithCache()
				upgrade = upgradeMap.CheckAndUpgrade(&preallocMap.MapInfo)
				c.Assert(upgrade, Equals, true)
				DisableMapPreAllocation()

				return []*Map{upgradeMap, preallocMap}
			},
			postRun: func(maps ...*Map) {
				for _, m := range maps {
					path, _ := m.Path()
					os.Remove(path)

					m.Close()
				}
			},
		},
		{
			name: "MapTypeLRUHash on 4.9 kernel: no prealloc to no prealloc upgrade",
			run: func() []*Map {
				// Asserts that maps with type MapTypeLRUHash on 4.9 kernels
				// are normalized to MapTypeHash and that when preallocation is
				// disabled, maps can be recreated without requiring them to be
				// removed due to a flag mismatch (upgrade).

				// Specify 4.9 kernel supported maps types and disable preallocation.
				setMapTypesFromProber(newMockProber(mapTypes49))
				DisableMapPreAllocation()

				upgradeMap := NewMap("cilium_test_upgrade",
					MapTypeLRUHash,
					&TestKey{},
					int(unsafe.Sizeof(TestKey{})),
					&TestValue{},
					int(unsafe.Sizeof(TestValue{})),
					maxEntries,
					0,
					0,
					ConvertKeyValue).WithCache()
				_, err := upgradeMap.OpenOrCreate()
				c.Assert(err, IsNil)

				// Typically, MapTypeLRUHash requires preallocation. Given the
				// underlying lack of LRU support in 4.9 kernels, this map type
				// would actually use MapTypeHash.
				//
				// Since the map type is switched to hashmap, now preallocation
				// can be disabled. When we try to upgrade the map, defining
				// that its type should be LRU, there's no intermediate state
				// where we decide that the map should be upgraded because the
				// desired type is LRU (or the preallocation flags are
				// mismatched).
				//
				// Instead, every single time the map info is evaluated, the
				// type & flags are evaluated first and then the upgrade
				// decision is made based on the attributes afterwards.
				//
				// In this case, we disabled preallocation and attempting to
				// upgrade the map of type LRU results in a no-op because it
				// was normalized to hashmap.
				upgrade := upgradeMap.CheckAndUpgrade(&upgradeMap.MapInfo)
				c.Assert(upgrade, Equals, false)

				return []*Map{upgradeMap}
			},
			postRun: func(maps ...*Map) {
				for _, m := range maps {
					path, _ := m.Path()
					os.Remove(path)

					m.Close()
				}
			},
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		maps := tt.run()
		tt.postRun(maps...)
	}
}

func (s *BPFPrivilegedTestSuite) TestUnpin(c *C) {
	var exist bool
	unpinMap := NewMap("cilium_test_unpin",
		MapTypeHash,
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue).WithCache()
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

	err = UnpinMapIfExists("cilium_test_unpin")
	c.Assert(err, IsNil)
	_, err = unpinMap.OpenOrCreate()
	c.Assert(err, IsNil)
	err = UnpinMapIfExists("cilium_test_unpin")
	c.Assert(err, IsNil)
	exist, err = unpinMap.exist()
	c.Assert(err, IsNil)
	c.Assert(exist, Equals, false)
}

func (s *BPFPrivilegedTestSuite) TestCreateUnpinned(c *C) {
	m := NewMap("cilium_test_create_unpinned",
		MapTypeHash,
		&TestKey{},
		int(unsafe.Sizeof(TestKey{})),
		&TestValue{},
		int(unsafe.Sizeof(TestValue{})),
		maxEntries,
		BPF_F_NO_PREALLOC,
		0,
		ConvertKeyValue).WithCache()
	err := m.CreateUnpinned()
	c.Assert(err, IsNil)
	exist, err := m.exist()
	c.Assert(err, IsNil)
	c.Assert(exist, Equals, false)

	key1 := &TestKey{Key: 105}
	value1 := &TestValue{Value: 205}
	err = m.Update(key1, value1)
	c.Assert(err, IsNil)

	var value2 TestValue
	err = LookupElement(m.fd, unsafe.Pointer(key1), unsafe.Pointer(&value2))
	c.Assert(err, IsNil)
	c.Assert(*value1, Equals, value2)
}

func newMockProber(mt probes.MapTypes) *mockProber {
	return &mockProber{
		mt: mt,
	}
}

func (m *mockProber) Probe() probes.Features {
	var f probes.Features
	f.MapTypes = m.mt
	return f
}

type mockProber struct {
	mt probes.MapTypes
}

// mapTypes49 represents the supported map types on 4.9 kernels.
var mapTypes49 = probes.MapTypes{
	HaveHashMapType:                true,
	HaveArrayMapType:               true,
	HaveProgArrayMapType:           true,
	HavePerfEventArrayMapType:      true,
	HavePercpuHashMapType:          true,
	HavePercpuArrayMapType:         true,
	HaveStackTraceMapType:          true,
	HaveCgroupArrayMapType:         true,
	HaveLruHashMapType:             false,
	HaveLruPercpuHashMapType:       false,
	HaveLpmTrieMapType:             false,
	HaveArrayOfMapsMapType:         false,
	HaveHashOfMapsMapType:          false,
	HaveDevmapMapType:              false,
	HaveSockmapMapType:             false,
	HaveCpumapMapType:              false,
	HaveXskmapMapType:              false,
	HaveSockhashMapType:            false,
	HaveCgroupStorageMapType:       false,
	HaveReuseportSockarrayMapType:  false,
	HavePercpuCgroupStorageMapType: false,
	HaveQueueMapType:               false,
	HaveStackMapType:               false,
}
