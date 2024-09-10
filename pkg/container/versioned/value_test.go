// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioned

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionedValue(t *testing.T) {
	var value1 Value[[]uint32]

	cv := Coordinator{
		Cleaner: func(keepVersion KeepVersion) {
			value1.RemoveBefore(keepVersion)
		},
	}

	// Initially empty
	handle := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle))
	assert.Nil(t, handle.Close())
	// 2nd call does nothing
	assert.NotNil(t, handle.Close())

	// Add first value
	handle1 := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle1))

	tx := cv.PrepareNextVersion()

	assert.Nil(t, value1.SetAt([]uint32{100, 200}, tx))
	assert.Nil(t, tx.Commit())

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
	assert.Nil(t, value1.SetAt([]uint32{100, 150, 200}, tx))
	assert.Nil(t, tx.Commit())

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
	assert.Nil(t, value1.RemoveAt(tx))
	assert.Nil(t, tx.Commit())

	// new handle sees an empty value
	handle4 := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle4))
	assert.Empty(t, value1.At(handle))
	v = value1.At(handle3)
	assert.Equal(t, []uint32{100, 150, 200}, v)
	v = value1.At(handle2)
	assert.Equal(t, []uint32{100, 200}, v)

	// closers can be called in any order
	assert.Nil(t, handle2.Close())
	assert.Nil(t, handle1.Close())

	// stale handle should now get an empty value after it's closer has been called and a new
	// value has been inserted
	assert.Empty(t, value1.At(handle2))

	v = value1.At(handle3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	assert.Nil(t, handle3.Close())

	assert.Empty(t, value1.At(handle3))

	assert.Nil(t, handle4.Close())

	// old values have been cleaned off
	assert.Nil(t, value1.head.Load())
}

func TestVersionedValueMultiple(t *testing.T) {
	var value1 Value[[]uint32]
	var value2 Value[[]uint32]

	cv := Coordinator{
		Cleaner: func(keepVersion KeepVersion) {
			value1.RemoveBefore(keepVersion)
			value2.RemoveBefore(keepVersion)
		},
	}

	// Initially empty
	handle := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle))
	assert.Empty(t, value2.At(handle))
	assert.Nil(t, handle.Close())
	assert.NotNil(t, handle.Close())

	// Add first values
	handle1 := cv.GetVersionHandle()
	assert.Empty(t, value1.At(handle1))
	assert.Empty(t, value2.At(handle1))

	tx := cv.PrepareNextVersion()

	assert.Nil(t, value1.SetAt([]uint32{100, 200}, tx))
	assert.Nil(t, value2.SetAt([]uint32{110, 190}, tx))
	assert.Nil(t, tx.Commit())

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
	assert.Nil(t, value1.SetAt([]uint32{100, 150, 200}, tx))
	assert.Nil(t, value2.SetAt([]uint32{110, 150, 190}, tx))
	assert.Nil(t, tx.Commit())

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
	assert.Nil(t, value1.RemoveAt(tx))
	assert.Nil(t, tx.Commit())

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
	assert.Nil(t, handle2.Close())
	assert.Nil(t, handle3.Close())
	assert.Nil(t, handle1.Close())
	assert.Nil(t, handle4.Close())

	// old value1 have been cleaned off
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
	n := s.ForEachBefore(KeepVersion(3), func(i int) {
		values = append(values, i)
	})
	assert.Equal(t, []int{2000, 1000}, values)
	s = s[n:]

	// get all values upto and including maxVersion; get the lone value
	values = nil
	n = s.ForEachBefore(KeepVersion(invalidVersion), func(i int) {
		values = append(values, i)
	})
	assert.Equal(t, []int{3000}, values)
	s = s[n:]
	assert.Len(t, s, 0)
}
