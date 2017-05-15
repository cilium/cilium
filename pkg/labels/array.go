// Copyright 2016-2017 Authors of Cilium
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

package labels

// LabelArray is an array of labels forming a set
type LabelArray []*Label

// Contains returns true if all ls contains all the labels in needed. If
// needed contains no labels, Contains() will always return true
func (ls LabelArray) Contains(needed LabelArray) bool {
nextLabel:
	for _, neededLabel := range needed {
		for _, l := range ls {
			if neededLabel.Matches(l) {
				continue nextLabel
			}
		}

		return false
	}

	return true
}

// Resolve resolves all labels in the array by calling Resolve() on each label
func (ls LabelArray) Resolve(owner LabelOwner) {
	for _, l := range ls {
		l.Resolve(owner)
	}
}

// Has returns whether the provided label exists.
func (ls LabelArray) Has(label string) bool {
	key := ParseKey(label)
	if key == "" {
		return false
	}
	for _, lsl := range ls {
		lslKey := ParseKey(lsl.String())
		// We are ignoring source to since the caller of this
		// function is probably running within the same source
		if lslKey == key {
			return true
		}
	}
	return false
}

// Get returns the value for the provided label.
func (ls LabelArray) Get(label string) string {
	key := ParseKey(label)
	if key == "" {
		return ""
	}
	for _, lsl := range ls {
		lslKey := ParseKey(lsl.String())
		if lslKey == key {
			return lsl.GetValue()
		}
	}
	return ""
}
