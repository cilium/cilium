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

import (
	"sort"
	"strings"
)

// LabelArray is an array of labels forming a set
type LabelArray []Label

// Sort is an internal utility to return all LabelArrays in sorted
// order, when the source material may be unsorted.  'ls' is sorted
// in-place, but also returns the sorted array for convenience.
func (ls LabelArray) Sort() LabelArray {
	sort.Slice(ls, func(i, j int) bool {
		return ls[i].Key < ls[j].Key
	})
	return ls
}

// ParseLabelArray parses a list of labels and returns a LabelArray
func ParseLabelArray(labels ...string) LabelArray {
	array := make(LabelArray, len(labels))
	for i := range labels {
		array[i] = ParseLabel(labels[i])
	}
	return array.Sort()
}

// ParseSelectLabelArray parses a list of select labels and returns a LabelArray
func ParseSelectLabelArray(labels ...string) LabelArray {
	array := make(LabelArray, len(labels))
	for i := range labels {
		array[i] = ParseSelectLabel(labels[i])
	}
	return array.Sort()
}

// ParseLabelArrayFromArray converts an array of strings as labels and returns a LabelArray
func ParseLabelArrayFromArray(base []string) LabelArray {
	array := make(LabelArray, len(base))
	for i := range base {
		array[i] = ParseLabel(base[i])
	}
	return array.Sort()
}

// NewLabelArrayFromSortedList returns labels based on the output of SortedList()
// Trailing ';' will result in an empty key that must be filtered out.
func NewLabelArrayFromSortedList(list string) LabelArray {
	base := strings.Split(list, ";")
	array := make(LabelArray, 0, len(base))
	for _, v := range base {
		if lbl := ParseLabel(v); lbl.Key != "" {
			array = append(array, lbl)
		}
	}
	return array
}

// ParseSelectLabelArrayFromArray converts an array of strings as select labels and returns a LabelArray
func ParseSelectLabelArrayFromArray(base []string) LabelArray {
	array := make(LabelArray, len(base))
	for i := range base {
		array[i] = ParseSelectLabel(base[i])
	}
	return array.Sort()
}

// Labels returns the LabelArray as Labels
func (ls LabelArray) Labels() Labels {
	lbls := Labels{}
	for _, l := range ls {
		lbls[l.Key] = l
	}
	return lbls
}

// Contains returns true if all ls contains all the labels in needed. If
// needed contains no labels, Contains() will always return true
func (ls LabelArray) Contains(needed LabelArray) bool {
nextLabel:
	for i := range needed {
		for l := range ls {
			if needed[i].Matches(&ls[l]) {
				continue nextLabel
			}
		}

		return false
	}

	return true
}

// Lacks is identical to Contains but returns all missing labels
func (ls LabelArray) Lacks(needed LabelArray) LabelArray {
	missing := LabelArray{}
nextLabel:
	for i := range needed {
		for l := range ls {
			if needed[i].Matches(&ls[l]) {
				continue nextLabel
			}
		}

		missing = append(missing, needed[i])
	}

	return missing
}

// Has returns whether the provided key exists.
// Implementation of the k8s.io/apimachinery/pkg/labels.Labels interface.
func (ls LabelArray) Has(key string) bool {
	// The key is submitted in the form of `source.key=value`
	keyLabel := parseSelectLabel(key, '.')
	if keyLabel.IsAnySource() {
		for l := range ls {
			if ls[l].Key == keyLabel.Key {
				return true
			}
		}
	} else {
		for _, lsl := range ls {
			// Note that if '=value' is part of 'key' it is ignored here
			if lsl.Source == keyLabel.Source && lsl.Key == keyLabel.Key {
				return true
			}
		}
	}
	return false
}

// Get returns the value for the provided key.
// Implementation of the k8s.io/apimachinery/pkg/labels.Labels interface.
func (ls LabelArray) Get(key string) string {
	keyLabel := parseSelectLabel(key, '.')
	if keyLabel.IsAnySource() {
		for l := range ls {
			if ls[l].Key == keyLabel.Key {
				return ls[l].Value
			}
		}
	} else {
		for _, lsl := range ls {
			if lsl.Source == keyLabel.Source && lsl.Key == keyLabel.Key {
				return lsl.Value
			}
		}
	}
	return ""
}

// DeepCopy returns a deep copy of the labels.
func (ls LabelArray) DeepCopy() LabelArray {
	if ls == nil {
		return nil
	}

	o := make(LabelArray, len(ls), len(ls))
	copy(o, ls)
	return o
}

// GetModel returns the LabelArray as a string array with fully-qualified labels.
// The output is parseable by ParseLabelArrayFromArray
func (ls LabelArray) GetModel() []string {
	res := []string{}
	for l := range ls {
		res = append(res, ls[l].String())
	}
	return res
}

func (ls LabelArray) String() string {
	res := "["
	for l := range ls {
		if l > 0 {
			res += " "
		}
		res += ls[l].String()
	}
	res += "]"
	return res
}

// Same returns true if the label arrays are the same, i.e., have the same labels in the same order.
func (ls LabelArray) Same(b LabelArray) bool {
	if len(ls) != len(b) {
		return false
	}
	for l := range ls {
		if !ls[l].Equals(&b[l]) {
			return false
		}
	}
	return true
}
