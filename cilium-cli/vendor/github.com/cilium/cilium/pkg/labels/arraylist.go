// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

// Merge incorporates new LabelArrays into an existing LabelArrayList, without
// introducing duplicates, returning the result for convenience. The LabelArrays
// contained in either LabelArrayList must already be sorted. Existing
// duplication in either list is not removed.
func (lsp *LabelArrayList) Merge(include ...LabelArray) LabelArrayList {
	lsp.Sort()
	incl := LabelArrayList(include).Sort()
	return lsp.mergeSorted(incl)
}

func (lsp *LabelArrayList) mergeSorted(include LabelArrayList) LabelArrayList {
	ls := *lsp
	merged := make(LabelArrayList, 0, len(include)+len(ls))

	var i, j int
	for i < len(include) && j < len(ls) {
		if ls[j].Less(include[i]) {
			merged = append(merged, ls[j])
			j++
		} else if ls[j].Equals(include[i]) {
			merged = append(merged, ls[j])
			i++
			j++
		} else {
			merged = append(merged, include[i])
			i++
		}
	}

	merged = append(merged, ls[j:]...)
	merged = append(merged, include[i:]...)
	*lsp = merged
	return merged
}
