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

package set

// SliceSubsetOf checks whether the first slice is a subset of the second slice. If
// not, it also returns slice of elements which are the difference of both
// input slices.
func SliceSubsetOf(sub, main []string) (bool, []string) {
	var diff []string
	occurrences := make(map[string]int, len(main))
	result := true
	for _, element := range main {
		occurrences[element]++
	}
	for _, element := range sub {
		if count, ok := occurrences[element]; !ok {
			// Element was not found in the main slice.
			result = false
			diff = append(diff, element)
		} else if count < 1 {
			// The element is in both slices, but the sub slice
			// has more duplicates.
			result = false
		} else {
			occurrences[element]--
		}
	}
	return result, diff
}
