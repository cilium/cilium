// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package set

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func (t empty) String() string { return "" }

type test struct{ c int }

func (t test) String() string { return "" }

type Member fmt.Stringer

func TestSet(t *testing.T) {
	require.True(t, Set[Member]{}.Empty())
	require.True(t, NewSet[Member]().Empty())
	require.False(t, NewSet[Member](nil).Empty())
	require.Equal(t, 1, NewSet[Member](nil).Len())

	var emptyItem empty
	var alsoEmptyItem empty

	require.False(t, NewSet[Member](emptyItem).Empty())
	require.Equal(t, 1, NewSet[Member](emptyItem).Len())

	require.Equal(t, 2, NewSet[Member](emptyItem, nil).Len())
	require.Equal(t, 2, NewSet[Member](nil, emptyItem).Len())

	// item and item2 are the same
	require.Equal(t, 2, NewSet[Member](emptyItem, nil, alsoEmptyItem).Len())
	require.Equal(t, 2, NewSet[Member](nil, alsoEmptyItem, emptyItem).Len())

	item1 := test{1}
	item2 := test{2}
	var anySeen, item1Seen, item2Seen, nilSeen, emptySeen bool
	set := NewSet[Member]()
	require.True(t, set.Empty())
	for range set.Members() {
		anySeen = true
	}
	require.False(t, anySeen)
	require.True(t, set.Insert(nil))
	for m := range set.Members() {
		anySeen = true
		if m == nil {
			nilSeen = true
		}
	}
	require.True(t, anySeen)
	require.True(t, nilSeen)
	require.Equal(t, 1, set.Len())
	require.False(t, set.Insert(nil))
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
	require.False(t, set.Remove(test{1})) // storage for set itself not changed
	require.Equal(t, 3, set.Len())

	for m := range set.Members() {
		anySeen = true
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
	}
	require.True(t, anySeen)
	require.False(t, item1Seen)
	require.True(t, item2Seen)
	require.True(t, nilSeen)
	require.True(t, emptySeen)

	// remove nil item
	require.False(t, set.Remove(nil)) // storage for set itself not changed
	require.Equal(t, 2, set.Len())

	// remove nil again
	require.False(t, set.Remove(nil)) // storage for set itself not changed
	require.Equal(t, 2, set.Len())

	item1Seen = false
	item2Seen = false
	nilSeen = false
	emptySeen = false
	for m := range set.Members() {
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
	}
	require.False(t, item1Seen)
	require.True(t, item2Seen)
	require.False(t, nilSeen)
	require.True(t, emptySeen)

	// remove empty item, storage should change from map to a singular item
	require.True(t, set.Remove(alsoEmptyItem))
	require.Equal(t, 1, set.Len())

	// remove last item
	require.True(t, set.Remove(item2))
	require.Equal(t, 0, set.Len())
	require.True(t, set.Empty())

	// nil handling corner cases

	// nil inserted as first item, correctly shifted to the internal map after another item is
	// inserted
	set = Set[Member]{}
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
	require.True(t, set.Remove(item1))
	require.Equal(t, 1, set.Len())
	require.False(t, set.Empty())
	require.True(t, set.Has(nil))
	require.False(t, set.Has(item1))

	require.True(t, set.Remove(nil))
	require.True(t, set.Empty())
	require.False(t, set.Has(nil))
	require.False(t, set.Remove(nil))

	// Equal
	item3 := test{3}
	item4 := test{4}
	require.True(t, Set[Member]{}.Equal(Set[Member]{}))
	require.True(t, Set[Member]{}.Equal(NewSet[Member]()))
	require.True(t, NewSet[Member]().Equal(NewSet[Member]()))
	require.False(t, NewSet[Member]().Equal(NewSet[Member](nil)))
	require.False(t, NewSet[Member](nil).Equal(NewSet[Member]()))
	require.True(t, NewSet[Member](nil).Equal(NewSet[Member](nil)))
	require.True(t, NewSet[Member](nil, item1).Equal(NewSet[Member](item1, nil)))
	require.False(t, NewSet[Member]().Equal(NewSet[Member](item2)))
	require.False(t, NewSet[Member](item1).Equal(NewSet[Member]()))
	require.False(t, NewSet(item1).Equal(NewSet(item2)))
	require.False(t, NewSet(item1).Equal(NewSet(item2)))
	require.False(t, NewSet(item1, item2).Equal(NewSet(item2)))
	require.False(t, NewSet(item1).Equal(NewSet(item2, item1)))
	require.True(t, NewSet(item1, item2).Equal(NewSet(item2, item1)))
	require.False(t, NewSet(item1, item2, item3).Equal(NewSet(item1, item2, item4)))

	// Clone
	set = NewSet[Member](item1, emptyItem, nil)
	set2 := set.Clone()
	require.True(t, set2.Equal(set))
	// modify set, set2 not changed
	require.False(t, set.Remove(nil))
	require.False(t, set2.Equal(set))
	require.True(t, set2.Has(nil))

	set = NewSet[Member](item1)
	set2 = set.Clone()
	require.True(t, set2.Equal(set))
	// Trying to remove non-existing item changes nothing
	require.False(t, set.Remove(nil))
	require.True(t, set2.Equal(set))
	require.True(t, set.Has(item1))
	require.True(t, set2.Has(item1))
	// modify set2, set not changed
	require.True(t, set2.Remove(item1))
	require.False(t, set.Equal(set2)) // storage changed
	require.True(t, set.Has(item1))
	require.False(t, set2.Has(item1))

	// Insert a set into another
	set = NewSet[Member](nil)
	set2 = NewSet[Member](emptyItem, item2, item1)
	require.True(t, set.Merge(set2)) // storage changed from single item to a map
	require.Equal(t, 4, set.Len())
	require.Equal(t, 3, set2.Len())
	require.True(t, set.Has(item2))
	require.False(t, set2.Has(nil))

	// Typed Members sees only the selected type elements
	emptySeen = false
	otherSeen := false
	require.Equal(t, 4, set.Len())
	for m := range MembersOfType[empty](set) {
		if m == emptyItem {
			emptySeen = true
		} else {
			otherSeen = true
		}
	}
	require.True(t, emptySeen)
	require.False(t, otherSeen)
	set3 := NewSet[Member](item3)
	require.Equal(t, 1, set3.Len())
	emptySeen = false
	otherSeen = false
	for m := range MembersOfType[empty](set3) {
		if m == emptyItem {
			emptySeen = true
		} else {
			otherSeen = true
		}
	}
	require.False(t, emptySeen)
	require.False(t, otherSeen)

	// RemoveSets
	set = NewSet[Member](nil)
	set2 = NewSet[Member](emptyItem, item3)
	set3 = NewSet[Member](item3)
	require.True(t, set.Merge(set2)) // storage changed
	require.Equal(t, 3, set.Len())
	require.False(t, set.RemoveSets(set3))
	require.Equal(t, 2, set.Len())
	require.True(t, set.RemoveSets(set2)) // storagechanged
	require.Equal(t, 1, set.Len())

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
			set2.Remove(item)
			require.Less(t, set2.Len(), len)
		}
	}
	require.True(t, set2.Empty())
}
