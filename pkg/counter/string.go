// Copyright 2019 Authors of Cilium
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
