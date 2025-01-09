// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"sort"
)

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

// Diff returns the string of differences between 'ls' and 'expected' LabelArrayList with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging. Assumes sorted LabelArrayLists.
func (ls LabelArrayList) Diff(expected LabelArrayList) (res string) {
	res += ""
	i := 0
	j := 0
	for i < len(ls) && j < len(expected) {
		if ls[i].Equals(expected[j]) {
			i++
			j++
			continue
		}
		if ls[i].Less(expected[j]) {
			// obtained has an unexpected labelArray
			res += "    + " + ls[i].String() + "\n"
			i++
		}
		for j < len(expected) && expected[j].Less(ls[i]) {
			// expected has a missing labelArray
			res += "    - " + expected[j].String() + "\n"
			j++
		}
	}
	for i < len(ls) {
		// obtained has an unexpected labelArray
		res += "    + " + ls[i].String() + "\n"
		i++
	}
	for j < len(expected) {
		// expected has a missing labelArray
		res += "    - " + expected[j].String() + "\n"
		j++
	}

	return res
}

// GetModel returns the LabelArrayList as a [][]string. Each member LabelArray
// becomes a []string.
func (ls LabelArrayList) String() string {
	res := ""
	for _, v := range ls {
		if res != "" {
			res += ", "
		}
		res += v.String()
	}
	return res
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
// introducing duplicates, returning the result for convenience. Existing
// duplication in either list is not removed.
func (lsp *LabelArrayList) Merge(include ...LabelArray) LabelArrayList {
	lsp.Sort()
	incl := LabelArrayList(include).Sort()
	return lsp.MergeSorted(incl)
}

// MergeSorted incorporates new labels from 'include' to the receiver,
// both of which must be already sorted.
// LabelArrays are inserted from 'include' to the receiver as needed.
func (lsp *LabelArrayList) MergeSorted(include LabelArrayList) LabelArrayList {
	merged := *lsp
	i := 0
	for j := 0; i < len(include) && j < len(merged); j++ {
		if include[i].Less(merged[j]) {
			merged = append(merged[:j+1], merged[j:]...) // make space at merged[j]
			merged[j] = include[i]
			i++
		} else if include[i].Equals(merged[j]) {
			i++
		}
	}

	// 'include' may have more entries after original labels have been exhausted
	if i < len(include) {
		merged = append(merged, include[i:]...)
	}

	*lsp = merged
	return *lsp
}
