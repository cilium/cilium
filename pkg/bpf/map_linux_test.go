// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
const (
	tick    = 100 * time.Millisecond
	timeout = 10 * time.Second
)

type BPFPrivilegedTestSuite struct {
	teardown func() error
}

type TestKey struct {
	Key uint32
}
type TestValue struct {
	Value uint32
}

func (k *TestKey) String() string { return fmt.Sprintf("key=%d", k.Key) }
func (k *TestKey) New() MapKey    { return &TestKey{} }

func (v *TestValue) String() string { return fmt.Sprintf("value=%d", v.Value) }
func (v *TestValue) New() MapValue  { return &TestValue{} }

var _ = Suite(&BPFPrivilegedTestSuite{})

func (s *BPFPrivilegedTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	CheckOrMountFS("")

	if err := rlimit.RemoveMemlock(); err != nil {
		c.Fatal(err)
	}

	if err := testMap.OpenOrCreate(); err != nil {
		c.Fatal("Failed to create map:", err)
	}

	s.teardown = func() error {
		testMap.Close()

		path, err := testMap.Path()
		if err != nil {
			return err
		}

		return os.Remove(path)
	}
}

func (s *BPFPrivilegedTestSuite) TearDownSuite(c *C) {
	if s.teardown != nil {
		if err := s.teardown(); err != nil {
			c.Fatal(err)
		}
	}
}

var (
	maxEntries = 16

	testMap = NewMap("cilium_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC,
	).WithCache()
)

func mapsEqual(a, b *Map) bool {
	return a.name == b.name &&
		reflect.DeepEqual(a.spec, b.spec)
}

func (s *BPFPrivilegedTestSuite) TestOpen(c *C) {
	// Ensure that os.IsNotExist() can be used with Map.Open()
	noSuchMap := NewMap("cilium_test_no_exist",
		ebpf.Hash, &TestKey{}, &TestValue{}, maxEntries, 0)
	err := noSuchMap.Open()
	c.Assert(errors.Is(err, os.ErrNotExist), Equals, true)

	// existingMap is the same as testMap. Opening should succeed.
	existingMap := NewMap("cilium_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).WithCache()
	err = existingMap.Open()
	c.Check(err, IsNil)      // Avoid assert to ensure Close() is called below.
	err = existingMap.Open() // Reopen should be no-op.
	c.Check(err, IsNil)
	err = existingMap.Close()
	c.Assert(err, IsNil)
}

func (s *BPFPrivilegedTestSuite) TestOpenMap(c *C) {
	openedMap, err := OpenMap("cilium_test_no_exist", &TestKey{}, &TestValue{})
	c.Assert(err, Not(IsNil))
	c.Assert(openedMap, IsNil)

	openedMap, err = OpenMap(MapPath("cilium_test"), &TestKey{}, &TestValue{})
	c.Assert(err, IsNil)

	c.Assert(mapsEqual(openedMap, testMap), Equals, true)
}

func (s *BPFPrivilegedTestSuite) TestOpenOrCreate(c *C) {
	// existingMap is the same as testMap. OpenOrCreate should skip recreation.
	existingMap := NewMap("cilium_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).WithCache()
	err := existingMap.OpenOrCreate()
	c.Assert(err, IsNil)

	// preallocMap unsets BPF_F_NO_PREALLOC. OpenOrCreate should recreate map.
	EnableMapPreAllocation() // prealloc on/off is controllable in HASH map case.
	preallocMap := NewMap("cilium_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		0).WithCache()
	err = preallocMap.OpenOrCreate()
	defer preallocMap.Close()
	c.Assert(err, IsNil)
	DisableMapPreAllocation()

	// preallocMap is already open. OpenOrCreate does nothing.
	err = preallocMap.OpenOrCreate()
	c.Assert(err, IsNil)
}

func (s *BPFPrivilegedTestSuite) TestRecreateMap(c *C) {
	parallelMap := NewMap("cilium_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).WithCache()
	err := parallelMap.Recreate()
	defer parallelMap.Close()
	c.Assert(err, IsNil)

	err = parallelMap.Recreate()
	c.Assert(err, Not(IsNil))

	// Check OpenMap warning section
	c.Assert(mapsEqual(parallelMap, testMap), Equals, true)

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
}

func (s *BPFPrivilegedTestSuite) TestBasicManipulation(c *C) {

	// existingMap is the same as testMap. Opening should succeed.
	existingMap := NewMap("cilium_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).
		WithCache().
		WithEvents(option.BPFEventBufferConfig{Enabled: true, MaxSize: 10})

	err := existingMap.Open()
	defer existingMap.Close()
	c.Assert(err, IsNil)

	key1 := &TestKey{Key: 103}
	value1 := &TestValue{Value: 203}
	key2 := &TestKey{Key: 104}
	value2 := &TestValue{Value: 204}

	dumpEvents := func() []*Event {
		es := []*Event{}
		existingMap.DumpAndSubscribe(func(e *Event) {
			es = append(es, e)
		}, false)
		return es
	}
	event := func(i int) *Event {
		es := dumpEvents()
		if i >= len(es) {
			return nil
		}
		return dumpEvents()[i]
	}
	assertEvent := func(i int, key, value, desiredAction, action string) {
		e := event(i)
		if e.cacheEntry.Key != nil {
			c.Assert(e.cacheEntry.Key.String(), Equals, key)
		}
		c.Assert(e.GetValue(), Equals, value)
		c.Assert(e.cacheEntry.DesiredAction.String(), Equals, desiredAction)
		c.Assert(e.GetAction(), Equals, action)
	}

	// event buffer should be empty
	c.Assert(existingMap.events.buffer.Size(), Equals, 0)

	err = existingMap.Update(key1, value1)
	c.Assert(err, IsNil)

	// Check events buffer
	c.Assert(len(dumpEvents()), Equals, 1)
	c.Assert(event(0).cacheEntry.Key.String(), Equals, "key=103")
	c.Assert(event(0).cacheEntry.Value.String(), Equals, "value=203")

	// key    val
	// 103    203
	value, err := existingMap.Lookup(key1)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value1)
	value, err = existingMap.Lookup(key2)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)

	// Check events buffer, ensure it doesn't change.
	c.Assert(len(dumpEvents()), Equals, 1)
	c.Assert(event(0).cacheEntry.Key.String(), Equals, "key=103")
	c.Assert(event(0).cacheEntry.Value.String(), Equals, "value=203")

	err = existingMap.Update(key1, value2)
	c.Assert(err, IsNil)
	// key    val
	// 103    204
	value, err = existingMap.Lookup(key1)
	c.Assert(err, IsNil)
	c.Assert(value, checker.DeepEquals, value2)

	// Check events buffer after second Update
	c.Assert(len(dumpEvents()), Equals, 2)
	assertEvent(0, "key=103", "value=203", "sync", "update")
	c.Assert(event(0).cacheEntry.Key.String(), Equals, "key=103")
	c.Assert(event(0).cacheEntry.Value.String(), Equals, "value=203")
	c.Assert(event(0).cacheEntry.DesiredAction.String(), Equals, "sync")
	c.Assert(event(1).cacheEntry.Key.String(), Equals, "key=103") // we used key1 again
	c.Assert(event(1).cacheEntry.Value.String(), Equals, "value=204")
	c.Assert(event(1).cacheEntry.DesiredAction.String(), Equals, "sync")

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

	c.Assert(len(dumpEvents()), Equals, 3)
	assertEvent(0, "key=103", "value=203", "sync", "update")
	assertEvent(1, "key=103", "value=204", "sync", "update")
	assertEvent(2, "key=104", "value=204", "sync", "update")

	err = existingMap.Delete(key1)
	c.Assert(err, IsNil)
	// key    val
	// 104    204
	value, err = existingMap.Lookup(key1)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)

	err = existingMap.Delete(key1)
	c.Assert(err, Not(IsNil))

	c.Assert(len(dumpEvents()), Equals, 5)
	assertEvent(0, "key=103", "value=203", "sync", "update")
	assertEvent(1, "key=103", "value=204", "sync", "update")
	assertEvent(2, "key=104", "value=204", "sync", "update")
	assertEvent(3, "key=103", "<nil>", Delete.String(), "delete")
	assertEvent(4, "key=103", "<nil>", Delete.String(), "delete")
	c.Assert(event(3).GetLastError(), IsNil)
	c.Assert(event(4).GetLastError(), Not(IsNil))

	deleted, err := existingMap.SilentDelete(key1)
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, false)

	c.Assert(len(dumpEvents()), Equals, 6)
	assertEvent(5, "key=103", "<nil>", Delete.String(), "delete")
	c.Assert(event(5).GetLastError(), IsNil)

	err = existingMap.Update(key1, value1)
	c.Assert(err, IsNil)

	c.Assert(len(dumpEvents()), Equals, 7)
	assertEvent(6, "key=103", "value=203", OK.String(), "update")

	deleted, err = existingMap.SilentDelete(key1)
	c.Assert(err, IsNil)
	c.Assert(deleted, Equals, true)

	c.Assert(len(dumpEvents()), Equals, 8)
	assertEvent(7, "key=103", "<nil>", Delete.String(), "delete")

	value, err = existingMap.Lookup(key1)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)

	err = existingMap.DeleteAll()
	c.Assert(err, IsNil)
	value, err = existingMap.Lookup(key1)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)
	value, err = existingMap.Lookup(key2)
	c.Assert(err, Not(IsNil))
	c.Assert(value, Equals, nil)

	c.Assert(len(dumpEvents()), Equals, 9)
	assertEvent(8, "key=104", "<nil>", "sync", "delete-all")

	c.Assert(event(0).cacheEntry.Key.String(), Equals, "key=103")
	c.Assert(event(0).cacheEntry.Value.String(), Equals, "value=203")

	c.Assert(event(0).cacheEntry.Key.String(), Equals, "key=103") // we used key1 again

	err = existingMap.Update(key2, value2)
	c.Assert(err, IsNil)
	c.Assert(len(dumpEvents()), Equals, 10) // full buffer
	assertEvent(9, "key=104", "value=204", OK.String(), "update")

	key3 := &TestKey{Key: 999}
	err = existingMap.Update(key3, value2)
	c.Assert(err, IsNil)
	c.Assert(len(dumpEvents()), Equals, 10) // full buffer
	assertEvent(0, "key=103", "value=204", OK.String(), "update")
	assertEvent(9, "key=999", "value=204", OK.String(), "update")

	key4 := &TestKey{Key: 1000}
	err = existingMap.Update(key4, value2)
	c.Assert(err, IsNil)
	err = existingMap.DeleteAll()
	c.Assert(err, IsNil)
	assertEvent(9, "<nil>", "<nil>", OK.String(), MapDeleteAll.String())

	// cleanup
	err = existingMap.DeleteAll()
	c.Assert(err, IsNil)
}

func (s *BPFPrivilegedTestSuite) TestSubscribe(c *C) {
	existingMap := NewMap("cilium_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).
		WithCache().
		WithEvents(option.BPFEventBufferConfig{Enabled: true, MaxSize: 10})

	subHandle, err := existingMap.DumpAndSubscribe(nil, true)
	c.Assert(err, IsNil)

	collect := 0
	done := make(chan struct{})
	go func(collect *int) {
		defer subHandle.Close()
		for range subHandle.C() {
			*collect++
		}
		close(done)
	}(&collect)

	key1 := &TestKey{Key: 103}
	value1 := &TestValue{Value: 203}
	err = existingMap.Update(key1, value1)
	c.Assert(err, IsNil)
	err = existingMap.Update(key1, value1)
	c.Assert(err, IsNil)
	err = existingMap.Delete(key1)
	c.Assert(err, IsNil)

	subHandle.Close()
	<-done
	c.Assert(collect, Equals, 3)

	// cleanup
	err = existingMap.DeleteAll()
	existingMap.events = nil
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
		ebpf.Hash, &TestKey{}, &TestValue{}, maxEntries, 0)
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

// TestDumpReliablyWithCallbackOveralapping attempts to test that DumpReliablyWithCallback
// will reliably iterate all keys that are known to be in a map, even if keys that are ahead
// of the current iteration can be deleted or updated concurrently.
// This test is not deterministic, it establishes a condition where we have keys that are known
// to be in the map and other keys which are volatile.  The test passes if the dump can reliably
// iterate all keys that are not volatile.
func (s *BPFPrivilegedTestSuite) TestDumpReliablyWithCallbackOveralapping(c *C) {
	iterations := 10000
	maxEntries := uint32(128)
	m := NewMap("cilium_dump_test2",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		int(maxEntries),
		BPF_F_NO_PREALLOC).WithCache()
	err := m.OpenOrCreate()
	c.Assert(err, IsNil)
	defer func() {
		path, _ := m.Path()
		os.Remove(path)
	}()
	defer m.Close()

	// Prepopulate the map.
	for i := uint32(0); i < maxEntries; i++ {
		err := m.Update(&TestKey{Key: i}, &TestValue{Value: i + 200})
		c.Check(err, IsNil)
	}

	// used to block the update/delete goroutine so that both start at aprox the same time.
	start := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := sync.WaitGroup{}
	wg.Add(1)
	// This goroutine will continuously delete and reinsert even keys.
	// Thus, when this is running in parallel with DumpReliablyWithCallback
	// it is unclear whether any even key will be iterated.
	go func() {
		defer wg.Done()
		<-start
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			for i := uint32(0); i < maxEntries; i += 2 {
				m.Delete(&TestKey{Key: i})
				err := m.Update(&TestKey{Key: i}, &TestValue{Value: i + 200})
				c.Check(err, IsNil)
			}
		}
	}()

	// We expect that DumpReliablyWithCallback will iterate all odd key/value pairs
	// even if the even keys are being deleted and reinserted.
	expect := map[string]string{}
	for i := uint32(0); i < maxEntries; i++ {
		if i%2 != 0 {
			expect[fmt.Sprintf("key=%d", i)] = fmt.Sprintf("value=%d", i+200)
		}
	}
	close(start) // start testing.
	for i := 0; i < iterations; i++ {
		dump := map[string]string{}
		ds := NewDumpStats(m)
		err := m.DumpReliablyWithCallback(func(key MapKey, value MapValue) {
			k := key.(*TestKey).Key
			if k%2 != 0 {
				k := key.(*TestKey).Key
				ks := dump[fmt.Sprintf("key=%d", k)]
				if _, ok := dump[ks]; ok {
					c.FailNow()
				}
				dump[fmt.Sprintf("key=%d", key.(*TestKey).Key)] = fmt.Sprintf("value=%d", value.(*TestValue).Value)
			}
		}, ds)
		if err == nil {
			c.Check(dump, checker.DeepEquals, expect)
		} else {
			c.Check(err, Equals, ErrMaxLookup)
		}
	}
	cancel()
	wg.Wait()
}

// TestDumpReliablyWithCallback tests that DumpReliablyWithCallback by concurrently
// upserting/removing keys in range [0, 4) in the map and then continuously dumping
// the map.
// The test validates that all keys that are not being removed/added are contained in the dump.
func (s *BPFPrivilegedTestSuite) TestDumpReliablyWithCallback(c *C) {
	maxEntries := uint32(256)
	m := NewMap("cilium_dump_test",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		int(maxEntries),
		BPF_F_NO_PREALLOC).WithCache()
	err := m.OpenOrCreate()
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
	// CheckAndUpgrade removes map file if upgrade is needed
	// so we setup and use another map.
	upgradeMap := NewMap("cilium_test_upgrade",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).WithCache()
	err := upgradeMap.OpenOrCreate()
	c.Assert(err, IsNil)
	defer func() {
		_ = upgradeMap.Unpin()
		upgradeMap.Close()
	}()

	// Exactly the same MapInfo so it won't be upgraded.
	upgrade := upgradeMap.CheckAndUpgrade(upgradeMap)
	c.Assert(upgrade, Equals, false)

	// preallocMap unsets BPF_F_NO_PREALLOC so upgrade is needed.
	EnableMapPreAllocation()
	preallocMap := NewMap("cilium_test_upgrade",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		0).WithCache()
	upgrade = upgradeMap.CheckAndUpgrade(preallocMap)
	c.Assert(upgrade, Equals, true)
	DisableMapPreAllocation()
}

func (s *BPFPrivilegedTestSuite) TestUnpin(c *C) {
	var exist bool
	unpinMap := NewMap("cilium_test_unpin",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).WithCache()
	err := unpinMap.OpenOrCreate()
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

	err = unpinMap.Unpin()
	c.Assert(err, IsNil)
	err = unpinMap.OpenOrCreate()
	c.Assert(err, IsNil)
	err = unpinMap.Unpin()
	c.Assert(err, IsNil)
	exist, err = unpinMap.exist()
	c.Assert(err, IsNil)
	c.Assert(exist, Equals, false)
}

func (s *BPFPrivilegedTestSuite) TestCreateUnpinned(c *C) {
	m := NewMap("cilium_test_create_unpinned",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		maxEntries,
		BPF_F_NO_PREALLOC).WithCache()
	err := m.CreateUnpinned()
	c.Assert(err, IsNil)
	exist, err := m.exist()
	c.Assert(err, IsNil)
	c.Assert(exist, Equals, false)

	k := &TestKey{Key: 105}
	v := &TestValue{Value: 205}
	err = m.Update(k, v)
	c.Assert(err, IsNil)

	got, err := m.Lookup(k)
	c.Assert(err, IsNil)
	c.Assert(got, checker.DeepEquals, v)
}

func BenchmarkMapLookup(b *testing.B) {
	b.ReportAllocs()

	m := NewMap("",
		ebpf.Hash,
		&TestKey{},
		&TestValue{},
		1,
		BPF_F_NO_PREALLOC)

	if err := m.CreateUnpinned(); err != nil {
		b.Fatal(err)
	}

	k := TestKey{Key: 0}
	if err := m.Update(&k, &TestValue{Value: 1}); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		if _, err := m.Lookup(&k); err != nil {
			b.Fatal(err)
		}
	}
}

func TestErrorResolver(t *testing.T) {
	testutils.PrivilegedTest(t)
	CheckOrMountFS("")
	require.NoError(t, rlimit.RemoveMemlock())

	var (
		key1, key2 = TestKey{Key: 10}, TestKey{Key: 20}
		val1, val2 = TestValue{1}, TestValue{2}
	)

	tests := []struct {
		name        string
		remove      func(t *testing.T, m *Map)
		expectedKey TestKey
		expectedVal TestValue
	}{
		{
			name:        "remove inserted element",
			remove:      func(t *testing.T, m *Map) { require.NoError(t, m.Delete(&key1), "Failed to remove element from map") },
			expectedKey: key2,
			expectedVal: val2,
		},
		{
			name:        "remove failing element",
			remove:      func(t *testing.T, m *Map) { require.Error(t, m.Delete(&key2), "Removal from map should have failed") },
			expectedKey: key1,
			expectedVal: val1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMap("cilium_error_resolver_test",
				ebpf.Hash,
				&TestKey{},
				&TestValue{},
				1, // Only one entry, so that the second insertion will fail
				BPF_F_NO_PREALLOC,
			).WithCache()

			t.Cleanup(func() {
				// Let's make sure that there's no interference between tests
				mapControllers.RemoveControllerAndWait(m.controllerName())
			})

			require.NoError(t, m.CreateUnpinned(), "Failed to create map")
			require.NoError(t, m.Update(&key1, &val1), "Failed to insert element in map")

			// Let's attempt to insert a second element in the map, which will fail because the map can only hold one
			require.Error(t, m.Update(&key2, &val2), "Map insertion should have failed")

			// Let's now remove one of the two elements (the actual assertion depends on which element is to be removed)
			tt.remove(t, m)

			// Assert that the other element is eventually present and correct
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				value, err := m.Lookup(&tt.expectedKey)
				assert.NoError(c, err)
				if assert.NotNil(c, value) {
					assert.Equal(c, tt.expectedVal.Value, value.(*TestValue).Value)
				}
			}, timeout, tick)

			// Check that the error resolver controller eventually succeeds
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				models := mapControllers.GetStatusModel()
				for _, model := range models {
					if model.Name == m.controllerName() {
						assert.NotZero(c, model.Status.SuccessCount)
						assert.Greater(c, model.Status.LastSuccessTimestamp, model.Status.LastFailureTimestamp)
						return
					}
				}

				assert.Fail(c, "Expected controller status not found")
			}, timeout, tick)
		})
	}
}
