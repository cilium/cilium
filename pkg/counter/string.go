// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

// StringCounter tracks references for strings.
//
// No threadsafety is provided within this structure, the user is expected to
// handle concurrent access to this structure if it is used from multiple
// threads.
type StringCounter map[string]int

// Add increments the reference count for the specified string key.
func (s StringCounter) Add(key string) (changed bool) {
	value, exists := s[key]
	if !exists {
		changed = true
	}
	s[key] = value + 1
	return changed
}

// Delete decrements the reference count for the specified string key.
func (s StringCounter) Delete(key string) bool {
	value := s[key]
	if value <= 1 {
		delete(s, key)
		return true
	}
	s[key] = value - 1
	return false
}
