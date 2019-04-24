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

// MapSubsetOfSlice checks whether the map keys are a subset of the given slice.
// If not, it also returns slice of elements which are the difference between
// map keys and the slice.
func MapSubsetOfSlice(sub map[string]string, main []string) (bool, []string) {
	var diff []string
	occurences := make(map[string]int, len(main))
	result := true
	for _, element := range main {
		occurences[element]++
	}
	for key := range sub {
		if count, ok := occurences[key]; !ok {
			// Element was not found in the main slice.
			result = false
			diff = append(diff, key)
		} else if count < 1 {
			// The key is in both slices, but the sub slice
			// has more duplicates.
			result = false
		} else {
			occurences[key]--
		}
	}
	return result, diff
}
