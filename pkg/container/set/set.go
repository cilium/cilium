// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package set

import (
	"fmt"
	"iter"
	"maps"
	"slices"
)

type empty struct{}

// Set contains zero, one, or more members. A non-zero singleton is stored inline, while multiple
// members are held in a non-exported map. A singleton equal to the zero value of T is also held in
// the map so that it remains distinguishable from an empty Set without a separate boolean field.
type Set[T comparable] struct {
	single  T
	members map[T]empty
}

func (s Set[T]) hasSingle() bool {
	var zero T
	return s.members == nil && s.single != zero
}

// Empty returns 'true' if the set is empty.
func (s Set[T]) Empty() bool {
	return !s.hasSingle() && len(s.members) == 0
}

// Len returns the number of members in the set.
func (s Set[T]) Len() int {
	if s.hasSingle() {
		return 1
	}
	return len(s.members)
}

func (s Set[T]) String() string {
	if s.hasSingle() {
		return fmt.Sprintf("%v", s.single)
	}
	res := ""
	for m := range s.members {
		if res != "" {
			res += ","
		}
		res += fmt.Sprintf("%v", m)
	}
	return res
}

// NewSet returns a Set initialized to contain the members in 'members'.
func NewSet[T comparable](members ...T) Set[T] {
	s := Set[T]{}
	for _, member := range members {
		s.Insert(member)
	}
	return s
}

// Has returns 'true' if 'member' is in the set.
func (s Set[T]) Has(member T) bool {
	if s.hasSingle() {
		return s.single == member
	}
	_, ok := s.members[member]
	return ok
}

// Insert inserts a member to the set.
// Returns 'true' when '*s' value has changed,
// so that if it is stored by value the caller must knows to update the stored value.
func (s *Set[T]) Insert(member T) (changed bool) {
	if s.members != nil {
		length := len(s.members)
		if _, exists := s.members[member]; exists {
			return false
		}
		if length == 1 {
			// A zero-valued singleton uses the map representation. Replace that map
			// when growing the Set to preserve value-copy semantics for singletons.
			replacement := make(map[T]empty, 2)
			maps.Copy(replacement, s.members)
			replacement[member] = empty{}
			s.members = replacement
			return true
		}
		s.members[member] = empty{}
		return false
	}

	if s.hasSingle() {
		if member == s.single {
			return false
		}
		s.members = make(map[T]empty, 2)
		s.members[s.single] = empty{}
		var zero T
		s.single = zero
		s.members[member] = empty{}
		return true
	}

	var zero T
	if member == zero {
		s.members = make(map[T]empty, 1)
		s.members[member] = empty{}
	} else {
		s.single = member
	}
	return true
}

// Merge inserts members in 'o' into to the set 's'.
// Returns 'true' when '*s' value has changed,
// so that if it is stored by value the caller must knows to update the stored value.
func (s *Set[T]) Merge(sets ...Set[T]) (changed bool) {
	for _, other := range sets {
		for m := range other.Members() {
			changed = s.Insert(m) || changed
		}
	}
	return changed
}

// Remove removes a member from the set.
// Returns 'true' when '*s' value was changed, so that if it is stored by value the caller knows to
// update the stored value.
func (s *Set[T]) Remove(member T) (changed bool) {
	if s.members != nil {
		length := len(s.members)
		if _, exists := s.members[member]; !exists {
			return false
		}
		switch length {
		case 1:
			// Do not mutate the fallback map for a zero-valued singleton: another
			// value copy of this Set may still refer to it.
			s.members = nil
			return true
		case 2:
			delete(s.members, member)
			for m := range s.members {
				var zero T
				if m != zero {
					s.single = m
					s.members = nil
				}
			}
			return true
		}
		delete(s.members, member)
		return false
	}

	if s.hasSingle() && s.single == member {
		var zero T
		s.single = zero
		return true
	}
	return false
}

// RemoveSets removes one or more Sets from the receiver set.
// Returns 'true' when '*s' value was changed, so that if it is stored by value the caller knows to
// update the stored value.
func (s *Set[T]) RemoveSets(sets ...Set[T]) (changed bool) {
	for _, other := range sets {
		for m := range other.Members() {
			changed = s.Remove(m) || changed
		}
	}
	return changed
}

// Clear makes the set '*s' empty.
func (s *Set[T]) Clear() {
	var zero T
	s.single = zero
	s.members = nil
}

// Equal returns 'true' if the receiver and argument sets are the same.
func (s Set[T]) Equal(o Set[T]) bool {
	sLen := s.Len()
	oLen := o.Len()

	if sLen != oLen {
		return false
	}

	switch sLen {
	case 0:
		return true
	case 1:
		sMember, _ := s.Get()
		oMember, _ := o.Get()
		return sMember == oMember
	}
	// compare the elements of the maps
	for member := range s.members {
		if _, ok := o.members[member]; !ok {
			return false
		}
	}
	return true
}

// DeepEqual is same as Equal due to Set keys being comparable.
func (s *Set[T]) DeepEqual(o *Set[T]) bool {
	return s.Equal(*o)
}

func (in *Set[T]) DeepCopyInto(out *Set[T]) {
	*out = *in
	maps.Copy(out.members, in.members)
}

// Members returns an iterator for the members in the set.
func (s Set[T]) Members() iter.Seq[T] {
	return func(yield func(m T) bool) {
		if s.hasSingle() {
			yield(s.single)
		} else {
			for member := range s.members {
				if !yield(member) {
					return
				}
			}
		}
	}
}

// MembersOfType return an iterator for each member of type M in the set.
func MembersOfType[M any, T comparable](s Set[T]) iter.Seq[M] {
	return func(yield func(m M) bool) {
		if s.hasSingle() {
			if v, ok := any(s.single).(M); ok {
				yield(v)
			}
		} else {
			for m := range s.members {
				if v, ok := any(m).(M); ok {
					if !yield(v) {
						return
					}
				}
			}
		}
	}
}

// Get returns any one member from the set.
// Useful when it is known that the set has only one element.
func (s Set[T]) Get() (m T, found bool) {
	if s.hasSingle() {
		return s.single, true
	}
	for m = range s.members {
		return m, true
	}
	return m, false
}

// AsSlice converts the set to a slice.
func (s Set[T]) AsSlice() []T {
	return slices.Collect(s.Members())
}

// Clone returns a copy of the set.
func (s Set[T]) Clone() Set[T] {
	if s.members != nil {
		return Set[T]{members: maps.Clone(s.members)}
	}
	return s // singular value or empty Set
}
