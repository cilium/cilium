// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioned

import (
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/lock"
)

type testCleaner struct {
	oldestVersion atomicVersion
	cleanerMutex  lock.Mutex
	cleanerCond   *sync.Cond
}

func newTestCleaner() *testCleaner {
	c := &testCleaner{}
	c.cleanerCond = sync.NewCond(&c.cleanerMutex)
	return c
}

func (c *testCleaner) waitUntilOldest(t *testing.T, version version) {
	c.cleanerMutex.Lock()
	for oldest := c.oldestVersion.load(); oldest < version; oldest = c.oldestVersion.load() {
		t.Logf("Waiting due to oldest %d < %d version\n", oldest, version)
		c.cleanerCond.Wait()
	}
	c.cleanerMutex.Unlock()
}

func (c *testCleaner) cleanValue(keepVersion KeepVersion, value *Value[[]uint32]) {
	c.cleanerMutex.Lock()
	defer c.cleanerMutex.Unlock()

	// 'keepVersion' may be older than 'oldestVersion', keep oldestVersion monotonically
	// increasing
	oldest := c.oldestVersion.load()
	if oldest < version(keepVersion) {
		value.RemoveBefore(keepVersion)
		c.oldestVersion.store(version(keepVersion))
		c.cleanerCond.Signal()
	}
}

func (c *testCleaner) cleanValues(keepVersion KeepVersion, values []Value[[]uint32]) {
	c.cleanerMutex.Lock()
	defer c.cleanerMutex.Unlock()

	// 'keepVersion' may be older than 'oldestVersion', keep oldestVersion monotonically
	// increasing
	oldest := c.oldestVersion.load()
	if oldest < version(keepVersion) {
		// remove old versions for all values before bumping 'oldestVersion'
		for i := range values {
			values[i].RemoveBefore(keepVersion)
		}
		c.oldestVersion.store(version(keepVersion))
		c.cleanerCond.Signal()
	}
}

func TestVersionedValue(t *testing.T) {
	var value1 Value[[]uint32]

	cleaner := newTestCleaner()

	cv := Coordinator{
		Cleaner: func(keepVersion KeepVersion) {
			cleaner.cleanValue(keepVersion, &value1)
		},
	}

	// Initially empty
	handle := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle))
	assert.NoError(t, handle.Close())
	// 2nd call does nothing
	assert.Error(t, handle.Close())

	// Add first value
	handle1 := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle1))
	version1 := handle1.Version()

	tx := cv.PrepareNextVersion()
	assert.False(t, tx.After(KeepVersion(tx.nextVersion)))
	assert.True(t, tx.After(version1))

	assert.NoError(t, value1.SetAt([]uint32{100, 200}, tx))
	assert.NoError(t, tx.Commit())

	oldTx := tx
	tx = cv.PrepareNextVersion()
	assert.Equal(t, tx.nextVersion, oldTx.nextVersion+1)

	// New value is invisible for the old handle
	assert.Empty(t, value1.At(handle))

	// But is visible for any new handles
	handle2 := cv.GetVersionHandle()

	v := value1.At(handle2)
	assert.Equal(t, []uint32{100, 200}, v)

	// Set a new value
	tx = cv.PrepareNextVersion()
	assert.NoError(t, value1.SetAt([]uint32{100, 150, 200}, tx))
	assert.NoError(t, tx.Commit())

	// new handle sees the new value
	handle3 := cv.GetVersionHandle()
	v = value1.At(handle3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	// Old handle sees the previous value
	v = value1.At(handle2)
	assert.Equal(t, []uint32{100, 200}, v)

	// first handle still sees no value
	assert.Empty(t, value1.At(handle))

	// delete the value at next version
	tx = cv.PrepareNextVersion()
	assert.NoError(t, value1.RemoveAt(tx))
	assert.NoError(t, tx.Commit())

	// new handle sees an empty value
	handle4 := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle4))
	assert.Empty(t, value1.At(handle))
	v = value1.At(handle3)
	assert.Equal(t, []uint32{100, 150, 200}, v)
	v = value1.At(handle2)
	assert.Equal(t, []uint32{100, 200}, v)

	// closers can be called in any order
	assert.NoError(t, handle2.Close())
	assert.NoError(t, handle1.Close())

	// stale handle should now get an empty value after it's closer has been called and a new
	// value has been inserted
	cleaner.waitUntilOldest(t, handle3.version)
	assert.Empty(t, value1.At(handle2))

	v = value1.At(handle3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	assert.NoError(t, handle3.Close())

	cleaner.waitUntilOldest(t, handle4.version)
	assert.Empty(t, value1.At(handle3))

	assert.NoError(t, handle4.Close())

	// old values have been cleaned off
	assert.Nil(t, value1.head.Load())
}

func TestVersionedValueMultiple(t *testing.T) {
	var value1 Value[[]uint32]
	var value2 Value[[]uint32]

	cleaner := newTestCleaner()

	cv := Coordinator{
		Cleaner: func(keepVersion KeepVersion) {
			cleaner.cleanValue(keepVersion, &value1)
			cleaner.cleanValue(keepVersion, &value2)
		},
	}

	// Initially empty
	handle := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle))
	assert.Empty(t, value2.At(handle))
	assert.NoError(t, handle.Close())
	assert.Error(t, handle.Close())

	// Add first values
	handle1 := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle1))
	assert.Empty(t, value2.At(handle1))

	tx := cv.PrepareNextVersion()

	assert.NoError(t, value1.SetAt([]uint32{100, 200}, tx))
	assert.NoError(t, value2.SetAt([]uint32{110, 190}, tx))
	assert.NoError(t, tx.Commit())

	oldTx := tx
	tx = cv.PrepareNextVersion()
	assert.Equal(t, tx.nextVersion, oldTx.nextVersion+1)

	// New value is invisible for the old handle
	assert.Empty(t, value1.At(handle1))
	assert.Empty(t, value2.At(handle1))

	// But is visible for any new handles
	handle2 := cv.GetVersionHandle()

	v := value1.At(handle2)
	assert.Equal(t, []uint32{100, 200}, v)

	v = value2.At(handle2)
	assert.Equal(t, []uint32{110, 190}, v)

	// New value appears at both values at the same version
	tx = cv.PrepareNextVersion()
	assert.NoError(t, value1.SetAt([]uint32{100, 150, 200}, tx))
	assert.NoError(t, value2.SetAt([]uint32{110, 150, 190}, tx))
	assert.NoError(t, tx.Commit())

	// new handle sees the new value
	handle3 := cv.GetVersionHandle()
	v = value1.At(handle3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	v = value2.At(handle3)
	assert.Equal(t, []uint32{110, 150, 190}, v)

	// Old handle sees the previous values
	v = value1.At(handle2)
	assert.Equal(t, []uint32{100, 200}, v)

	v = value2.At(handle2)
	assert.Equal(t, []uint32{110, 190}, v)

	// first handle still sees no value
	assert.Empty(t, value1.At(handle))

	// delete the value1 at next version
	tx = cv.PrepareNextVersion()
	assert.NoError(t, value1.RemoveAt(tx))
	assert.NoError(t, tx.Commit())

	// new handle sees an empty value1, but value2 remains
	handle4 := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle4))

	v = value2.At(handle4)
	assert.Equal(t, []uint32{110, 150, 190}, v)

	assert.Empty(t, value1.At(handle))
	assert.Empty(t, value2.At(handle))

	v = value1.At(handle3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	v = value2.At(handle3)
	assert.Equal(t, []uint32{110, 150, 190}, v)

	v = value1.At(handle2)
	assert.Equal(t, []uint32{100, 200}, v)

	v = value2.At(handle2)
	assert.Equal(t, []uint32{110, 190}, v)

	// handle closers can be called in any order
	assert.NoError(t, handle2.Close())
	assert.NoError(t, handle3.Close())
	assert.NoError(t, handle1.Close())
	assert.NoError(t, handle4.Close())

	// old value1 have been cleaned off
	cleaner.waitUntilOldest(t, tx.nextVersion)
	assert.Nil(t, value1.head.Load())

	// but value2 remains, as it was not removed
	assert.NotNil(t, value2.head.Load())
}

func TestPairSlice(t *testing.T) {
	cv := Coordinator{}
	s := make(VersionedSlice[int], 0, 10)

	// 1st value '2000' at version 1
	tx := cv.PrepareNextVersion()
	s = s.Append(2000, tx)
	assert.Len(t, s, 1)
	assert.Equal(t, version(1), s[0].version)
	assert.Equal(t, 2000, s[0].value)

	tx.Commit()
	tx = cv.PrepareNextVersion()

	// 2nd value '1000' at version 2
	s = s.Append(1000, tx)
	assert.Len(t, s, 2)
	assert.Equal(t, version(1), s[0].version)
	assert.Equal(t, 2000, s[0].value)
	assert.Equal(t, version(2), s[1].version)
	assert.Equal(t, 1000, s[1].value)

	tx.Commit()
	tx = cv.PrepareNextVersion()

	// 3rd value '3000' at version 3
	s = s.Append(3000, tx)
	assert.Len(t, s, 3)
	assert.Equal(t, version(1), s[0].version)
	assert.Equal(t, 2000, s[0].value)
	assert.Equal(t, version(2), s[1].version)
	assert.Equal(t, 1000, s[1].value)
	assert.Equal(t, version(3), s[2].version)
	assert.Equal(t, 3000, s[2].value)

	// get all values before version 3; excluding the last value
	var values []int
	n := 0
	for i := range s.Before(KeepVersion(3)) {
		values = append(values, i)
		n++
	}
	assert.Equal(t, []int{2000, 1000}, values)
	s = s[n:]

	// get all values upto and including maxVersion; get the lone value
	values = nil
	n = 0
	for i := range s.Before(KeepVersion(invalidVersion)) {
		values = append(values, i)
		n++
	}
	assert.Equal(t, []int{3000}, values)
	s = s[n:]
	assert.Empty(t, s)
}

func TestVersionedChaos(t *testing.T) {
	const nValues = 10
	values := make([]Value[[]uint32], nValues)

	cleaner := newTestCleaner()

	cv := Coordinator{
		Cleaner: func(keepVersion KeepVersion) {
			for range nValues {
				cleaner.cleanValues(keepVersion, values)
			}
		},
	}

	// Initially empty
	handle := cv.GetVersionHandle()
	for i := range nValues {
		assert.Empty(t, values[i].At(handle))
	}
	assert.NoError(t, handle.Close())
	assert.Error(t, handle.Close())

	var mutex lock.Mutex
	var writerWg, readerWg sync.WaitGroup
	for range 1000 {
		for range 100 {
			readerWg.Add(1)
			go func() {
				time.Sleep(time.Duration(rand.IntN(100)) * time.Millisecond)
				version := cv.GetVersionHandle()
				time.Sleep(time.Duration(rand.IntN(100)) * time.Millisecond)
				version.Close()
				readerWg.Done()
			}()
		}
		writerWg.Add(1)
		go func() {
			time.Sleep(time.Duration(rand.IntN(100)) * time.Millisecond)
			mutex.Lock()
			defer mutex.Unlock()
			// Add some values
			tx := cv.PrepareNextVersion()
			idx := rand.IntN(nValues)
			var value []uint32
			switch rand.IntN(5) {
			case 0:
				value = []uint32{}
			case 1:
				value = []uint32{1}
			case 2:
				value = []uint32{1, 2}
			case 3:
				value = []uint32{1, 2, 3}
			case 4:
				value = []uint32{1, 2, 3, 4}
			case 5:
				value = []uint32{1, 2, 3, 4, 5}
			}
			assert.NoError(t, values[idx].SetAt(value, tx))
			tx.Commit()
			writerWg.Done()
		}()
	}

	t.Logf("Waiting until all writers are done\n")
	writerWg.Wait()

	mutex.Lock()
	defer mutex.Unlock()

	tx := cv.PrepareNextVersion()
	for i := range nValues {
		assert.NoError(t, values[i].RemoveAt(tx))
	}
	tx.Commit()

	t.Logf("Waiting until oldest version is %d\n", tx.nextVersion)
	cleaner.waitUntilOldest(t, tx.nextVersion)

	// Check that all values were removed
	for i := range nValues {
		assert.Nil(t, values[i].head.Load())
	}

	t.Logf("Waiting until all readers are done\n")
	readerWg.Wait()
}
