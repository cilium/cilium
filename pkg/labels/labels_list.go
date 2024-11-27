// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"slices"
	"sort"
)

type LabelsList []Labels

func (ll LabelsList) DeepEqual(other *LabelsList) bool {
	if other == nil {
		return false
	}
	return ll.Equal(*other)
}

// DeepCopy returns a deep copy of the labels list
func (ll LabelsList) DeepCopy() LabelsList {
	return slices.Clone(ll)
}

// GetModel returns the LabelsList as a [][]string. Each member Labels
// becomes a []string.
func (ls LabelsList) GetModel() [][]string {
	res := make([][]string, 0, len(ls))
	for _, v := range ls {
		res = append(res, v.GetModel())
	}
	return res
}

func (ls LabelsList) String() string {
	res := ""
	for _, v := range ls {
		if res != "" {
			res += ", "
		}
		res += v.String()
	}
	return res
}

// Equals returns true if the label arrays lists have the same labels in the same order.
func (ll LabelsList) Equal(other LabelsList) bool {
	return slices.EqualFunc(ll, other, Labels.Equal)
}

// Diff returns the string of differences between 'ls' and 'expected' LabelsList with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging. Assumes sorted LabelsLists.
func (ls LabelsList) Diff(expected LabelsList) (res string) {
	res += ""
	i := 0
	j := 0
	for i < len(ls) && j < len(expected) {
		if ls[i].Equal(expected[j]) {
			i++
			j++
			continue
		}
		if ls[i].Less(expected[j]) {
			// obtained has an unexpected labels
			res += "    + " + ls[i].String() + "\n"
			i++
		}
		for j < len(expected) && expected[j].Less(ls[i]) {
			// expected has a missing labels
			res += "    - " + expected[j].String() + "\n"
			j++
		}
	}
	for i < len(ls) {
		// obtained has an unexpected labels
		res += "    + " + ls[i].String() + "\n"
		i++
	}
	for j < len(expected) {
		// expected has a missing labels
		res += "    - " + expected[j].String() + "\n"
		j++
	}

	return res
}

// Sort sorts the LabelsList in-place, but also returns the sorted list
// for convenience.
func (ll LabelsList) Sort() LabelsList {
	sort.Slice(ll, func(i, j int) bool {
		return ll[i].Less(ll[j])
	})
	return ll
}

// Merge incorporates new Labels into an existing LabelsList, without
// introducing duplicates, returning the result for convenience. Existing
// duplication in either list is not removed.
func (lsp *LabelsList) Merge(include ...Labels) LabelsList {
	lsp.Sort()
	incl := LabelsList(include).Sort()
	return lsp.MergeSorted(incl)
}

// MergeSorted incorporates new labels from 'include' to the receiver,
// both of which must be already sorted.
// LabelArrays are inserted from 'include' to the receiver as needed.
func (lsp *LabelsList) MergeSorted(include LabelsList) LabelsList {
	merged := *lsp
	i := 0
	for j := 0; i < len(include) && j < len(merged); j++ {
		if include[i].Less(merged[j]) {
			merged = append(merged[:j+1], merged[j:]...) // make space at merged[j]
			merged[j] = include[i]
			i++
		} else if include[i].Equal(merged[j]) {
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
