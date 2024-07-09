// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"maps"
)

// Member is an empty interface to hold values in Set
type Member interface{}

// Set contains zero, one, or more Members. Zero or one members do not consume any additional
// storage, more than one members are held in a map
type Set struct {
	// members can be:
	// - empty (default condition)
	// - a singular value:
	//   - nil membersMap for a singlular zero valued interface member
	//   - any singular interface value
	// - membersMap that contains 2 or more interface values, which can be 'nil'
	members Member
}

// memberMap holds members when more than one is needed
type memberMap map[Member]struct{}

// Set with a sole nil interface member is represented by an empty memberMap (nil map)
var nilMember memberMap

func newMemberMap(members ...Member) memberMap {
	// typically map is allocated when new member is first added, preallocate space for it
	m := make(memberMap, len(members)+1)
	for _, member := range members {
		m[member] = struct{}{}
	}
	return m
}

func NewSet(members ...Member) Set {
	s := Set{}
	for _, member := range members {
		s.Insert(member)
	}
	return s
}

func (s Set) Empty() bool {
	return s.members == nil
}

func (s Set) Len() int {
	if s.members == nil {
		return 0
	}
	if members, ok := s.members.(memberMap); ok {
		if members == nil {
			// special case for nil value in the Set
			return 1
		}
		return len(members)
	}
	return 1
}

func (s Set) Has(member Member) bool {
	if member != nil && s.members == member {
		return true
	}
	if members, ok := s.members.(memberMap); ok {
		if members == nil && member == nil {
			// Special case for singular nil value
			return true
		}
		_, ok := members[member]
		return ok
	}
	return false
}

func (s *Set) insert(member Member) (changed bool) {
	// Add first element?
	if s.members == nil {
		if member == nil {
			s.members = nilMember
		} else {
			s.members = member
		}
		return true
	}
	members, ok := s.members.(memberMap)
	if !ok || members == nil {
		if !ok {
			// One non-nil element in the Set
			if member == s.members {
				return false // already in
			}
			// move the singular value over to the new map before adding more
			members = newMemberMap(s.members)
		} else {
			// Sole 'nil' in the Set
			if member == nil {
				return false // already in
			}
			// move the singular 'nil' over to the new map before adding more
			members = newMemberMap(nil)
		}
		s.members = members
		changed = true
	}
	// add the new member
	members[member] = struct{}{}
	return changed
}

func (s *Set) insertAll(member Member) (changed bool) {
	if members, ok := member.(memberMap); ok {
		for member := range members {
			if s.insert(member) {
				changed = true
			}
		}
	} else {
		changed = s.insert(member)
	}
	return changed
}

// Insert inserts either a singular member, or a Set of Members to the set
func (s *Set) Insert(member Member) (changed bool) {
	switch v := member.(type) {
	case Set:
		// Insert members of the set instead the set itself
		return s.insertAll(v.members)
	case *Set:
		// Insert members of the set instead the set itself
		return s.insertAll(v.members)
	default:
		// add a singular member
		return s.insertAll(member)
	}
}

func (s *Set) remove(member Member) (found, changed bool) {
	members, ok := s.members.(memberMap)
	if !ok || members == nil {
		if !ok {
			// One non-nil element in the Set
			if member == s.members {
				s.members = nil
				return true, true
			}
		} else {
			// Sole 'nil' in the Set
			if member == nil {
				s.members = nil
				return true, true
			}
		}
	} else {
		oldLen := len(members)
		delete(members, member)
		newLen := len(members)
		if oldLen > newLen {
			if newLen == 1 {
				// get to the single value and place it in place of the map
				for member := range members {
					if member == nil {
						s.members = nilMember
					} else {
						s.members = member
					}
					changed = true
				}
			}
			return true, changed
		}
	}
	return false, false // not found, not changed
}

func (s *Set) removeAll(member Member) (found, changed bool) {
	if members, ok := member.(memberMap); ok {
		// remove members in the map
		for member := range members {
			var f bool
			f, changed = s.remove(member)
			if f {
				found = f
			}
		}
		return found, changed
	}
	return s.remove(member)
}

// Remove removes either a singular member, or a Set of Members from the set.
// Returns 'true, false' if member was removed, but 's' value did not change.
// Returns 'true, true' when member was removed and 's' value was changed,
// so that if it is held by value, that value needs to be updated.
func (s *Set) Remove(member Member) (found, changed bool) {
	switch v := member.(type) {
	case Set:
		// Remove members of the set instead the set itself
		return s.removeAll(v.members)
	case *Set:
		// Remove members of the set instead the set itself
		return s.removeAll(v.members)
	default:
		return s.removeAll(member)
	}
}

func (s *Set) Clear() {
	s.members = nil
}

func (s Set) Equal(o Set) bool {
	// Maps cannot be compared
	sMembers, sOk := s.members.(memberMap)
	oMembers, oOk := o.members.(memberMap)

	// Same singular members?
	if !sOk && !oOk && s.members == o.members || // same non-nil or both empty
		sOk && oOk && sMembers == nil && oMembers == nil { // same singual 'nil'
		return true
	}
	if s.members == nil || o.members == nil { // only one empty
		return false
	}

	// by this point both of them have to be same size memberMaps for the members to be the same
	if !sOk || !oOk || len(sMembers) != len(oMembers) {
		return false
	}

	for member := range sMembers {
		if _, ok := oMembers[member]; !ok {
			return false
		}
	}
	return true
}

func (s Set) ForEach(f func(m Member) bool) {
	if members, ok := s.members.(memberMap); ok {
		for member := range members {
			if !f(member) {
				return
			}
		}
	} else {
		f(s.members)
	}
}

func ForEach[T any](s Set, f func(m T) bool) {
	if members, ok := s.members.(memberMap); ok {
		for member := range members {
			if v, ok := member.(T); ok {
				if !f(v) {
					return
				}
			}
		}
	} else {
		if v, ok := s.members.(T); ok {
			f(v)
		}
	}
}

// Get any item from the set
func (s Set) Get() (Member, bool) {
	if s.members == nil {
		return nil, false
	}
	if members, ok := s.members.(memberMap); ok {
		if members == nil {
			return nil, true
		}
		for m := range members {
			return m, true
		}
	}
	return s.members, true
}

func (s Set) Clone() Set {
	if members, ok := s.members.(memberMap); ok && members != nil {
		return Set{members: maps.Clone(members)}
	}
	return s // singular or empty Set
}
