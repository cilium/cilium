// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type tf interface {
	Foo()
}
type empty struct{}

func (t *empty) Foo() {}

type test struct{ c int }

func (t *test) Foo() {}

func TestSet(t *testing.T) {
	require.True(t, Set{}.Empty())
	require.True(t, NewSet().Empty())
	require.False(t, NewSet(nil).Empty())
	require.Equal(t, 1, NewSet(nil).Len())

	var emptyItem empty
	var alsoEmptyItem empty

	require.False(t, NewSet(emptyItem).Empty())
	require.Equal(t, 1, NewSet(emptyItem).Len())

	require.Equal(t, 2, NewSet(emptyItem, nil).Len())
	require.Equal(t, 2, NewSet(nil, emptyItem).Len())

	// item and item2 are the same
	require.Equal(t, 2, NewSet(emptyItem, nil, alsoEmptyItem).Len())
	require.Equal(t, 2, NewSet(nil, alsoEmptyItem, emptyItem).Len())

	item1 := test{1}
	item2 := test{2}
	set := NewSet()
	require.True(t, set.Empty())
	require.True(t, set.Insert(nil))
	require.Equal(t, 1, set.Len())
	require.True(t, set.Insert(item1))
	require.Equal(t, 2, set.Len())
	require.False(t, set.Insert(emptyItem))
	require.Equal(t, 3, set.Len())
	require.False(t, set.Insert(item1))
	require.Equal(t, 3, set.Len())
	require.False(t, set.Insert(item2))
	require.Equal(t, 4, set.Len())

	require.True(t, set.Has(alsoEmptyItem))
	require.True(t, set.Has(emptyItem))
	require.True(t, set.Has(nil))
	require.True(t, set.Has(item1))
	require.True(t, set.Has(item2))

	// remove item1 using a duplicate
	found, changed := set.Remove(test{1})
	require.True(t, found)
	require.False(t, changed) // storage for set itself not changed
	require.Equal(t, 3, set.Len())

	var item1Seen, item2Seen, nilSeen, emptySeen bool
	set.ForEach(func(m Member) bool {
		if m == item1 {
			item1Seen = true
		}
		if m == item2 {
			item2Seen = true
		}
		if m == nil {
			nilSeen = true
		}
		if m == emptyItem {
			emptySeen = true
		}
		return true
	})
	require.False(t, item1Seen)
	require.True(t, item2Seen)
	require.True(t, nilSeen)
	require.True(t, emptySeen)

	// remove nil item
	found, changed = set.Remove(nil)
	require.True(t, found)
	require.False(t, changed) // storage for set itself not changed
	require.Equal(t, 2, set.Len())

	// remove nil again
	found, changed = set.Remove(nil)
	require.False(t, found)
	require.False(t, changed) // storage for set itself not changed
	require.Equal(t, 2, set.Len())

	item1Seen = false
	item2Seen = false
	nilSeen = false
	emptySeen = false
	set.ForEach(func(m Member) bool {
		if m == item1 {
			item1Seen = true
		}
		if m == item2 {
			item2Seen = true
		}
		if m == nil {
			nilSeen = true
		}
		if m == emptyItem {
			emptySeen = true
		}
		return true
	})
	require.False(t, item1Seen)
	require.True(t, item2Seen)
	require.False(t, nilSeen)
	require.True(t, emptySeen)

	// remove empty item, storage should change from map to a singular item
	found, changed = set.Remove(alsoEmptyItem)
	require.True(t, found)
	require.True(t, changed)
	require.Equal(t, 1, set.Len())

	// remove last item
	found, changed = set.Remove(item2)
	require.True(t, found)
	require.True(t, changed)
	require.Equal(t, 0, set.Len())
	require.True(t, set.Empty())

	// nil handling corner cases

	// nil inserted as first item, correctly shifted to the internal map after another item is
	// inserted
	set = Set{}
	require.True(t, set.Empty())
	require.Equal(t, 0, set.Len())
	require.False(t, set.Has(nil))

	require.True(t, set.Insert(nil))
	require.False(t, set.Empty())
	require.Equal(t, 1, set.Len())
	require.True(t, set.Has(nil))

	require.True(t, set.Insert(item1))
	require.Equal(t, 2, set.Len())
	require.True(t, set.Has(nil))
	require.True(t, set.Has(item1))

	// nil left as the last item
	found, changed = set.Remove(item1)
	require.True(t, found)
	require.True(t, changed)
	require.Equal(t, 1, set.Len())
	require.False(t, set.Empty())
	require.True(t, set.Has(nil))
	require.False(t, set.Has(item1))

	found, changed = set.Remove(nil)
	require.True(t, found)
	require.True(t, changed)
	require.True(t, set.Empty())
	require.False(t, set.Has(nil))

	// Equal
	require.True(t, Set{}.Equal(Set{}))
	require.True(t, Set{}.Equal(NewSet()))
	require.True(t, NewSet().Equal(NewSet()))
	require.False(t, NewSet().Equal(NewSet(nil)))
	require.False(t, NewSet(nil).Equal(NewSet()))
	require.True(t, NewSet(nil).Equal(NewSet(nil)))
	require.True(t, NewSet(nil, item1).Equal(NewSet(item1, nil)))
	require.False(t, NewSet().Equal(NewSet(item2)))
	require.False(t, NewSet(item1).Equal(NewSet()))
	require.False(t, NewSet(item1).Equal(NewSet(item2)))
	require.False(t, NewSet(item1).Equal(NewSet(item2)))
	require.False(t, NewSet(item1, item2).Equal(NewSet(item2)))
	require.False(t, NewSet(item1).Equal(NewSet(item2, item1)))
	require.True(t, NewSet(item1, item2).Equal(NewSet(item2, item1)))

	// Clone
	set = NewSet(item1, emptyItem, nil)
	set2 := set.Clone()
	require.True(t, set2.Equal(set))
	// modify set, set2 not changed
	found, changed = set.Remove(nil)
	require.True(t, found)
	require.False(t, changed)
	require.False(t, set2.Equal(set))
	require.True(t, set2.Has(nil))

	set = NewSet(item1)
	set2 = set.Clone()
	require.True(t, set2.Equal(set))
	// Trying to remove non-existing item changes nothing
	found, changed = set.Remove(nil)
	require.False(t, found)
	require.True(t, set2.Equal(set))
	require.True(t, set.Has(item1))
	require.True(t, set2.Has(item1))
	// modify set2, set not changed
	found, changed = set2.Remove(item1)
	require.True(t, found)
	require.True(t, changed)
	require.False(t, set.Equal(set2)) // storage changed
	require.True(t, set.Has(item1))
	require.False(t, set2.Has(item1))

	// Insert a set into another
	set = NewSet(nil)
	set2 = NewSet(emptyItem, item2, item1)
	changed = set.Insert(set2)
	require.True(t, changed) // storage changed from single item to a map
	require.Equal(t, 4, set.Len())
	require.Equal(t, 3, set2.Len())
	require.True(t, set.Has(item2))
	require.False(t, set2.Has(nil))

	// Typed ForEach sees only the selected type elements
	emptySeen = false
	require.Equal(t, 4, set.Len())
	ForEach(set, func(m empty) bool {
		if m == emptyItem {
			emptySeen = true
		}
		return true
	})
	require.True(t, emptySeen)

	// Clear
	set.Clear()
	require.True(t, set.Empty())

	// Get, empty set2 by Get/Remove
	ok := true
	for ok {
		var item Member
		if item, ok = set2.Get(); ok {
			require.NotNil(t, item)
			len := set2.Len()
			found, _ = set2.Remove(item)
			require.True(t, found)
			require.True(t, set2.Len() < len)
		}
	}
	require.True(t, set2.Empty())
}
