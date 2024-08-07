// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioned

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionedValue(t *testing.T) {
	var value1 Value[[]uint32]

	cv := NewVersionManager(func(keepVersion Version) {
		Cleaner(&value1, keepVersion)
	})

	// Initially empty
	handle := cv.GetHandle("empty")
	assert.Empty(t, GetValue(&value1, handle))
	assert.True(t, handle.Release())
	// 2ns call does nothing
	assert.False(t, handle.Release())

	// Add first value
	handle1 := cv.GetHandle("first")
	assert.Empty(t, GetValue(&value1, handle1))

	current, next := cv.GetVersion()
	assert.Less(t, current, next)

	SetValueAtVersion(&value1, []uint32{100, 200}, next)
	assert.True(t, cv.PublishVersion(current, next))

	current, _ = cv.GetVersion()
	assert.Equal(t, next, current)

	// New value is invisible for the old handle
	assert.Empty(t, GetValue(&value1, handle))

	// But is visible for any new handles
	handle2 := cv.GetHandle("second")

	v := GetValue(&value1, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{100, 200}, v)

	// Set a new value
	current, next = cv.GetVersion()
	SetValueAtVersion(&value1, []uint32{100, 150, 200}, next)
	assert.True(t, cv.PublishVersion(current, next))

	// new handle sees the new value
	handle3 := cv.GetHandle("third")
	v = GetValue(&value1, handle3)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	// Old handle sees the previous value
	v = GetValue(&value1, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{100, 200}, v)

	// first handle still sees no value
	assert.Empty(t, GetValue(&value1, handle))

	// delete the value at next version
	current, next = cv.GetVersion()
	RemoveValueAtVersion(&value1, next)
	assert.True(t, cv.PublishVersion(current, next))

	// new handle sees an empty value
	handle4 := cv.GetHandle("fourth")
	assert.Empty(t, GetValue(&value1, handle4))
	assert.Empty(t, GetValue(&value1, handle))
	v = GetValue(&value1, handle3)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{100, 150, 200}, v)
	v = GetValue(&value1, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{100, 200}, v)

	// closers can be called in any order
	assert.True(t, handle2.Release())
	assert.True(t, handle1.Release())

	// stale handle should now get an empty value after it's closer has been called and a new
	// value has been inserted
	assert.Empty(t, GetValue(&value1, handle2))

	v = GetValue(&value1, handle3)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	assert.True(t, handle3.Release())

	assert.Empty(t, GetValue(&value1, handle3))

	assert.True(t, handle4.Release())

	// old values have been cleaned off
	assert.Nil(t, value1.head.Load())
}

func TestVersionedValueMultiple(t *testing.T) {
	var value1 Value[[]uint32]
	var value2 Value[[]uint32]

	cv := NewVersionManager(func(keepVersion Version) {
		Cleaner(&value1, keepVersion)
		Cleaner(&value2, keepVersion)
	})

	// Initially empty
	handle := cv.GetHandle("empty")
	assert.Empty(t, GetValue(&value1, handle))
	assert.Empty(t, GetValue(&value2, handle))
	assert.True(t, handle.Release())
	assert.False(t, handle.Release())

	// Add first values
	handle1 := cv.GetHandle("first")
	assert.Empty(t, GetValue(&value1, handle1))
	assert.Empty(t, GetValue(&value2, handle1))

	current, next := cv.GetVersion()
	assert.Less(t, current, next)

	SetValueAtVersion(&value1, []uint32{100, 200}, next)
	SetValueAtVersion(&value2, []uint32{110, 190}, next)
	assert.True(t, cv.PublishVersion(current, next))

	current, _ = cv.GetVersion()
	assert.Equal(t, next, current)

	// New value is invisible for the old handle
	assert.Empty(t, GetValue(&value1, handle1))
	assert.Empty(t, GetValue(&value2, handle1))

	// But is visible for any new handles
	handle2 := cv.GetHandle("second")

	v := GetValue(&value1, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{100, 200}, v)

	v = GetValue(&value2, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{110, 190}, v)

	// New value appears at both values at the same version
	current, next = cv.GetVersion()
	SetValueAtVersion(&value1, []uint32{100, 150, 200}, next)
	SetValueAtVersion(&value2, []uint32{110, 150, 190}, next)
	assert.True(t, cv.PublishVersion(current, next))

	// new handle sees the new value
	handle3 := cv.GetHandle("third")
	v = GetValue(&value1, handle3)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	v = GetValue(&value2, handle3)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{110, 150, 190}, v)

	// Old handle sees the previous values
	v = GetValue(&value1, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{100, 200}, v)

	v = GetValue(&value2, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{110, 190}, v)

	// first handle still sees no value
	assert.Empty(t, GetValue(&value1, handle))

	// delete the value1 at next version
	current, next = cv.GetVersion()
	RemoveValueAtVersion(&value1, next)
	assert.True(t, cv.PublishVersion(current, next))

	// new handle sees an empty value1, but value2 remains
	handle4 := cv.GetHandle("fourth")
	assert.Empty(t, GetValue(&value1, handle4))

	v = GetValue(&value2, handle4)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{110, 150, 190}, v)

	assert.Empty(t, GetValue(&value1, handle))
	assert.Empty(t, GetValue(&value2, handle))

	v = GetValue(&value1, handle3)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{100, 150, 200}, v)

	v = GetValue(&value2, handle3)
	assert.Len(t, v, 3)
	assert.Equal(t, []uint32{110, 150, 190}, v)

	v = GetValue(&value1, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{100, 200}, v)

	v = GetValue(&value2, handle2)
	assert.Len(t, v, 2)
	assert.Equal(t, []uint32{110, 190}, v)

	// handle closers can be called in any order
	assert.True(t, handle2.Release())
	assert.True(t, handle3.Release())
	assert.True(t, handle1.Release())
	assert.True(t, handle4.Release())

	// old value1 have been cleaned off
	assert.Nil(t, value1.head.Load())

	// but value2 remains, as it was not removed
	assert.NotNil(t, value2.head.Load())
}

func TestPairSlice(t *testing.T) {
	var version Version
	s := NewPairSlice[int](10)

	// 1st value '2000' at version 0
	s = AppendPair(s, version, 2000)
	assert.Len(t, s, 1)
	assert.Equal(t, Version(0), s[0].version)
	assert.Equal(t, 2000, s[0].value)

	version++

	// 2nd value '1000' at version 1
	s = AppendPair(s, version, 1000)
	assert.Len(t, s, 2)
	assert.Equal(t, Version(0), s[0].version)
	assert.Equal(t, 2000, s[0].value)
	assert.Equal(t, Version(1), s[1].version)
	assert.Equal(t, 1000, s[1].value)

	// 3rd value '3000' at version 'maxVersion'
	s = AppendPair(s, maxVersion, 3000)
	assert.Len(t, s, 3)
	assert.Equal(t, Version(0), s[0].version)
	assert.Equal(t, 2000, s[0].value)
	assert.Equal(t, Version(1), s[1].version)
	assert.Equal(t, 1000, s[1].value)
	assert.Equal(t, maxVersion, s[2].version)
	assert.Equal(t, 3000, s[2].value)

	// get all values upto maxVersion - 1; excluding the last value
	var values []int
	n := ForEachUpToVersion(s, maxVersion-1, func(i int) {
		values = append(values, i)
	})

	assert.Equal(t, 2, n)
	assert.Equal(t, []int{2000, 1000}, values)

	assert.Len(t, s, 3)
	assert.Equal(t, 10, cap(s))

	// Trim the iterated values off the front
	s = TrimFrontPairSlice(s, n, 5)
	assert.Len(t, s, 1)
	assert.Equal(t, 8, cap(s))

	// get all values upto and including maxVersion; get the lone value
	values = nil
	n = ForEachUpToVersion(s, maxVersion, func(i int) {
		values = append(values, i)
	})

	assert.Equal(t, []int{3000}, values)
	assert.Equal(t, 1, n)

	assert.Len(t, s, 1)
	assert.Equal(t, 8, cap(s))

	// Trim the iterated value off the front, check that the  max capacity (5) is honored
	s = TrimFrontPairSlice(s, n, 5)
	assert.Len(t, s, 0)
	assert.NotNil(t, s)
	assert.Equal(t, 5, cap(s))
}
