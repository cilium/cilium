/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package set

// Set represents a set data structure.
type Set[T comparable] map[T]struct{}

// New returns an initialized set.
func New[T comparable]() Set[T] {
	return make(Set[T])
}

// Add adds item into the set s.
func (s Set[T]) Add(item T) {
	s[item] = struct{}{}
}

// Contains returns true if the set s contains item.
func (s Set[T]) Contains(item T) bool {
	_, ok := s[item]
	return ok
}

// Delete deletes an item from the set.
func (s Set[T]) Delete(item T) {
	delete(s, item)
}
