package stringutil

import (
	"fmt"

	"golang.org/x/exp/maps"
)

// unit is a convenient alias for struct{}
type unit = struct{}

// Set is a set of strings.
type Set struct {
	m map[string]unit
}

// NewSet returns a new string set containing strs.
func NewSet(strs ...string) (set *Set) {
	set = &Set{
		m: make(map[string]unit, len(strs)),
	}

	for _, s := range strs {
		set.Add(s)
	}

	return set
}

// Add adds s to the set.  Add panics if the set is a nil set, just like a nil
// map does.
func (set *Set) Add(s string) {
	set.m[s] = unit{}
}

// Clone returns a deep clone of set.  If set is nil, clone is nil.
func (set *Set) Clone() (clone *Set) {
	if set == nil {
		return nil
	}

	return &Set{
		m: maps.Clone(set.m),
	}
}

// Del deletes s from the set.  Calling Del on a nil set has no effect, just
// like delete on an empty map doesn't.
func (set *Set) Del(s string) {
	if set != nil {
		delete(set.m, s)
	}
}

// Equal returns true if set is equal to other.
func (set *Set) Equal(other *Set) (ok bool) {
	if set == nil || other == nil {
		return set == other
	} else if set.Len() != other.Len() {
		return false
	}

	for s := range set.m {
		if _, ok = other.m[s]; !ok {
			return false
		}
	}

	return true
}

// Has returns true if s is in the set.  Calling Has on a nil set returns false,
// just like indexing on an empty map does.
func (set *Set) Has(s string) (ok bool) {
	if set != nil {
		_, ok = set.m[s]
	}

	return ok
}

// Len returns the length of the set.  A nil set has a length of zero, just like
// an empty map.
func (set *Set) Len() (n int) {
	if set == nil {
		return 0
	}

	return len(set.m)
}

// Range calls f with each value of the set in an undefined order.  If cont is
// false, Range stops the iteration.  Calling Range on a nil *Set has no effect.
func (set *Set) Range(f func(s string) (cont bool)) {
	if set == nil {
		return
	}

	for s := range set.m {
		if !f(s) {
			break
		}
	}
}

// String implements the fmt.Stringer interface for *Set.
func (set *Set) String() (s string) {
	return fmt.Sprintf("%q", set.Values())
}

// Values returns all values in the set.  The order of the values is undefined.
// Values returns nil if the set is nil.
func (set *Set) Values() (strs []string) {
	if set == nil {
		return nil
	}

	strs = make([]string, 0, len(set.m))
	for s := range set.m {
		strs = append(strs, s)
	}

	return strs
}
