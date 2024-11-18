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

// Set contains zero, one, or more members. Zero or one members do not consume any additional
// storage, more than one members are held in an non-exported membersMap.
type Set[T comparable] struct {
	single  *T
	members map[T]empty
}

// Empty returns 'true' if the set is empty.
func (s Set[T]) Empty() bool {
	return s.single == nil && s.members == nil
}

// Len returns the number of members in the set.
func (s Set[T]) Len() int {
	if s.single != nil {
		return 1
	}
	return len(s.members)
}

func (s Set[T]) String() string {
	if s.single != nil {
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
	if s.single != nil {
		return *s.single == member
	}
	_, ok := s.members[member]
	return ok
}

// Insert inserts a member to the set.
// Returns 'true' when '*s' value has changed,
// so that if it is stored by value the caller must knows to update the stored value.
func (s *Set[T]) Insert(member T) (changed bool) {
	switch s.Len() {
	case 0:
		s.single = &member
		return true
	case 1:
		if member == *s.single {
			return false
		}
		s.members = make(map[T]empty, 2)
		s.members[*s.single] = empty{}
		s.single = nil
		s.members[member] = empty{}
		return true
	default:
		s.members[member] = empty{}
		return false
	}
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
	length := s.Len()
	switch length {
	case 0:
	case 1:
		if *s.single == member {
			s.single = nil
			return true
		}
	case 2:
		delete(s.members, member)
		if len(s.members) == 1 {
			for m := range s.members {
				s.single = &m
			}
			s.members = nil
			return true
		}
	default:
		delete(s.members, member)
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
	s.single = nil
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
		return *s.single == *o.single
	}
	// compare the elements of the maps
	for member := range s.members {
		if _, ok := o.members[member]; !ok {
			return false
		}
	}
	return true
}

// Members returns an iterator for the members in the set.
func (s Set[T]) Members() iter.Seq[T] {
	return func(yield func(m T) bool) {
		if s.single != nil {
			yield(*s.single)
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
		if s.single != nil {
			if v, ok := any(*s.single).(M); ok {
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
	length := s.Len()

	switch length {
	case 0:
	case 1:
		m = *s.single
	default:
		for m = range s.members {
			break
		}
	}
	return m, length > 0
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
