// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sets

import (
	"fmt"
	"sort"
	"strings"
)

// StringSet stores a set of unique string elements.
type StringSet struct {
	set map[string]present
}

// NewStringSet creates a StringSet containing the supplied initial string elements.
func NewStringSet(elements ...string) *StringSet {
	s := &StringSet{}
	s.set = make(map[string]present)
	s.Insert(elements...)
	return s
}

// Copy returns a newly allocated copy of the supplied StringSet.
func (s *StringSet) Copy() *StringSet {
	c := NewStringSet()
	if s != nil {
		for e := range s.set {
			c.set[e] = present{}
		}
	}
	return c
}

// Insert zero or more string elements into the StringSet.
// As expected for a Set, elements already present in the StringSet are
// simply ignored.
func (s *StringSet) Insert(elements ...string) {
	for _, e := range elements {
		s.set[e] = present{}
	}
}

// Delete zero or more string elements from the StringSet.
// Any elements not present in the StringSet are simply ignored.
func (s *StringSet) Delete(elements ...string) {
	for _, e := range elements {
		delete(s.set, e)
	}
}

// Intersect returns a new StringSet containing the intersection of the
// receiver and argument StringSets.  Returns an empty set if the argument is nil.
func (s *StringSet) Intersect(other *StringSet) *StringSet {
	if other == nil {
		return NewStringSet()
	}

	// Point a and b to the maps, setting a to the smaller of the two.
	a, b := s.set, other.set
	if len(b) < len(a) {
		a, b = b, a
	}

	// Perform the intersection.
	intersect := NewStringSet()
	for e := range a {
		if _, ok := b[e]; ok {
			intersect.set[e] = present{}
		}
	}
	return intersect
}

// Disjoint returns true if the intersection of the receiver and the argument
// StringSets is the empty set.  Returns true if the argument is nil or either
// StringSet is the empty set.
func (s *StringSet) Disjoint(other *StringSet) bool {
	if other == nil || len(other.set) == 0 || len(s.set) == 0 {
		return true
	}

	// Point a and b to the maps, setting a to the smaller of the two.
	a, b := s.set, other.set
	if len(b) < len(a) {
		a, b = b, a
	}

	// Check for non-empty intersection.
	for e := range a {
		if _, ok := b[e]; ok {
			return false // Early-exit because intersecting.
		}
	}
	return true
}

// Difference returns a new StringSet containing the elements in the receiver
// that are not present in the argument StringSet. Returns a copy of the
// receiver if the argument is nil.
func (s *StringSet) Difference(other *StringSet) *StringSet {
	if other == nil {
		return s.Copy()
	}

	// Insert only the elements in the receiver that are not present in the
	// argument StringSet.
	diff := NewStringSet()
	for e := range s.set {
		if _, ok := other.set[e]; !ok {
			diff.set[e] = present{}
		}
	}
	return diff
}

// Unique returns a new StringSet containing the elements in the receiver
// that are not present in the argument StringSet *and* the elements in the
// argument StringSet that are not in the receiver (which is the union of two
// disjoint sets). Returns a copy of the
// receiver if the argument is nil.
func (s *StringSet) Unique(other *StringSet) *StringSet {
	if other == nil {
		return s.Copy()
	}

	sNotInOther := s.Difference(other)
	otherNotInS := other.Difference(s)

	// Duplicate Union implementation here to avoid extra Copy, since both
	// sNotInOther and otherNotInS are already copies.
	unique := sNotInOther
	for e := range otherNotInS.set {
		unique.set[e] = present{}
	}
	return unique
}

// Equal returns true if the receiver and the argument StringSet contain
// exactly the same elements.
func (s *StringSet) Equal(other *StringSet) bool {
	if s == nil || other == nil {
		return s == nil && other == nil
	}

	// Two sets of different length cannot have the exact same unique elements.
	if len(s.set) != len(other.set) {
		return false
	}

	// Only one loop is needed. If the two sets are known to be of equal
	// length, then the two sets are equal only if exactly all of the elements
	// in the first set are found in the second.
	for e := range s.set {
		if _, ok := other.set[e]; !ok {
			return false
		}
	}

	return true
}

// Union returns a new StringSet containing the union of the receiver and
// argument StringSets.  Returns a copy of the receiver if the argument is nil.
func (s *StringSet) Union(other *StringSet) *StringSet {
	union := s.Copy()
	if other != nil {
		for e := range other.set {
			union.set[e] = present{}
		}
	}
	return union
}

// Contains returns true if element is in the StringSet.
func (s *StringSet) Contains(element string) bool {
	_, in := s.set[element]
	return in
}

// Len returns the number of unique elements in the StringSet.
func (s *StringSet) Len() int {
	return len(s.set)
}

// Empty returns true if the receiver is the empty set.
func (s *StringSet) Empty() bool {
	return len(s.set) == 0
}

// Elements returns a []string of the elements in the StringSet, in no
// particular (or consistent) order.
func (s *StringSet) Elements() []string {
	elements := []string{} // Return at least an empty slice rather than nil.
	for e := range s.set {
		elements = append(elements, e)
	}
	return elements
}

// Sorted returns a sorted []string of the elements in the StringSet.
func (s *StringSet) Sorted() []string {
	elements := s.Elements()
	sort.Strings(elements)
	return elements
}

// String formats the StringSet elements as sorted strings, representing them
// in "array initializer" syntax.
func (s *StringSet) String() string {
	elements := s.Sorted()
	var quoted []string
	for _, e := range elements {
		quoted = append(quoted, fmt.Sprintf("%q", e))
	}
	return fmt.Sprintf("{%s}", strings.Join(quoted, ", "))
}
