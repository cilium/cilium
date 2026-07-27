// Copyright (c) 2025 Karl Gaissmaier
// SPDX-License-Identifier: MIT

package golden

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
)

// Table is a simple and slow route table, implemented as a slice of prefixes
// and values as a golden reference for bart.
type Table[V any] []TableItem[V]

type TableItem[V any] struct {
	Pfx netip.Prefix
	Val V
}

func (g TableItem[V]) String() string {
	return fmt.Sprintf("(%s, %v)", g.Pfx, g.Val)
}

func (t *Table[V]) Insert(pfx netip.Prefix, val V) {
	pfx = pfx.Masked()
	for i, item := range *t {
		if item.Pfx == pfx {
			(*t)[i].Val = val // de-dupe
			return
		}
	}
	*t = append(*t, TableItem[V]{pfx, val})
}

func (t *Table[V]) Delete(pfx netip.Prefix) (exists bool) {
	pfx = pfx.Masked()

	for i, item := range *t {
		if item.Pfx == pfx {
			*t = slices.Delete(*t, i, i+1)
			return true
		}
	}
	return false
}

func (t Table[V]) AllSorted() []netip.Prefix {
	var result []netip.Prefix

	for _, item := range t {
		result = append(result, item.Pfx)
	}
	slices.SortFunc(result, cmpPrefix)
	return result
}

func (t Table[V]) Get(pfx netip.Prefix) (val V, ok bool) {
	pfx = pfx.Masked()
	for _, item := range t {
		if item.Pfx == pfx {
			return item.Val, true
		}
	}
	return val, false
}

func (t *Table[V]) Update(pfx netip.Prefix, cb func(V, bool) V) (val V) {
	pfx = pfx.Masked()
	for i, item := range *t {
		if item.Pfx == pfx {
			// update val
			val = cb(item.Val, true)
			(*t)[i].Val = val
			return val
		}
	}
	// new val
	val = cb(val, false)

	*t = append(*t, TableItem[V]{pfx, val})
	return val
}

func (ta *Table[V]) Union(tb *Table[V]) {
	for _, bItem := range *tb {
		var match bool
		for i, aItem := range *ta {
			if aItem.Pfx == bItem.Pfx {
				(*ta)[i] = bItem
				match = true
				break
			}
		}
		if !match {
			*ta = append(*ta, bItem)
		}
	}
}

func (t Table[V]) Lookup(addr netip.Addr) (val V, ok bool) {
	bestLen := -1

	for _, item := range t {
		if item.Pfx.Contains(addr) && item.Pfx.Bits() > bestLen {
			val = item.Val
			ok = true
			bestLen = item.Pfx.Bits()
		}
	}
	return val, ok
}

func (t Table[V]) LookupPrefix(pfx netip.Prefix) (val V, ok bool) {
	pfx = pfx.Masked()
	bestLen := -1

	for _, item := range t {
		if item.Pfx.Overlaps(pfx) && item.Pfx.Bits() <= pfx.Bits() && item.Pfx.Bits() > bestLen {
			val = item.Val
			ok = true
			bestLen = item.Pfx.Bits()
		}
	}
	return val, ok
}

func (t Table[V]) LookupPrefixLPM(pfx netip.Prefix) (lpm netip.Prefix, val V, ok bool) {
	pfx = pfx.Masked()
	bestLen := -1

	for _, item := range t {
		if item.Pfx.Overlaps(pfx) && item.Pfx.Bits() <= pfx.Bits() && item.Pfx.Bits() > bestLen {
			val = item.Val
			lpm = item.Pfx
			ok = true
			bestLen = item.Pfx.Bits()
		}
	}
	return lpm, val, ok
}

func (t Table[V]) Subnets(pfx netip.Prefix) []netip.Prefix {
	pfx = pfx.Masked()
	var result []netip.Prefix

	for _, item := range t {
		if pfx.Overlaps(item.Pfx) && pfx.Bits() <= item.Pfx.Bits() {
			result = append(result, item.Pfx)
		}
	}
	slices.SortFunc(result, cmpPrefix)
	return result
}

func (t Table[V]) Supernets(pfx netip.Prefix) []netip.Prefix {
	pfx = pfx.Masked()
	var result []netip.Prefix

	for _, item := range t {
		if item.Pfx.Overlaps(pfx) && item.Pfx.Bits() <= pfx.Bits() {
			result = append(result, item.Pfx)
		}
	}
	slices.SortFunc(result, cmpPrefix)
	slices.Reverse(result)
	return result
}

func (t Table[V]) OverlapsPrefix(pfx netip.Prefix) bool {
	pfx = pfx.Masked()
	for _, p := range t {
		if p.Pfx.Overlaps(pfx) {
			return true
		}
	}
	return false
}

func (ta *Table[V]) Overlaps(tb *Table[V]) bool {
	for _, aItem := range *ta {
		for _, bItem := range *tb {
			if aItem.Pfx.Overlaps(bItem.Pfx) {
				return true
			}
		}
	}
	return false
}

// Sort, inplace by netip.Prefix, all prefixes are in normalized form
func (t *Table[V]) Sort() {
	slices.SortFunc(*t, func(a, b TableItem[V]) int {
		return cmpPrefix(a.Pfx, b.Pfx)
	})
}

// cmpPrefix, helper function, compare func for prefix sort,
// all cidrs are already normalized
func cmpPrefix(a, b netip.Prefix) int {
	if cmpAddr := a.Addr().Compare(b.Addr()); cmpAddr != 0 {
		return cmpAddr
	}

	return cmp.Compare(a.Bits(), b.Bits())
}
