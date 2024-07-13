// Copyright 2018 Authors of Cilium
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

import "sort"

// LabelArrayList is an array of LabelArrays. It is primarily intended as a
// simple collection
type LabelArrayList []LabelArray

// DeepCopy returns a deep copy of the LabelArray, with each element also copied.
func (ls LabelArrayList) DeepCopy() LabelArrayList {
	if ls == nil {
		return nil
	}

	o := make(LabelArrayList, 0, len(ls))
	for _, v := range ls {
		o = append(o, v.DeepCopy())
	}
	return o
}

// GetModel returns the LabelArrayList as a [][]string. Each member LabelArray
// becomes a []string.
func (ls LabelArrayList) GetModel() [][]string {
	res := make([][]string, 0, len(ls))
	for _, v := range ls {
		res = append(res, v.GetModel())
	}
	return res
}

// Equals returns true if the label arrays lists have the same label arrays in the same order.
func (ls LabelArrayList) Equals(b LabelArrayList) bool {
	if len(ls) != len(b) {
		return false
	}
	for l := range ls {
		if !ls[l].Equals(b[l]) {
			return false
		}
	}
	return true
}

// Sort sorts the LabelArrayList in-place, but also returns the sorted list
// for convenience. The LabelArrays themselves must already be sorted. This is
// true for all constructors of LabelArray.
func (ls LabelArrayList) Sort() LabelArrayList {
	sort.Slice(ls, func(i, j int) bool {
		return ls[i].Less(ls[j])
	})

	return ls
}
