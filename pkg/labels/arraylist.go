// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"fmt"
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
		fmt.Printf("LEN DIFFERS: obtained %v, expected %v\n", ls, b)
		return false
	}
	for l := range ls {
		if !ls[l].Equals(b[l]) {
			fmt.Printf("LABEL ARRAY %d DIFFERS: obtained %v, expected %v\n",
				l, ls[l], b[l])
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

// MergeSorted returns a new LabelArrayList with all LabelArrays from a and b
// without changing a or b. a and b must be sorted already.
func MergeSorted(a, b LabelArrayList) LabelArrayList {
	merged := make(LabelArrayList, 0, len(a)+len(b))

	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i].Equals(b[j]):
			j++
			fallthrough
		case a[i].Less(b[j]):
			merged = append(merged, a[i])
			i++
		default:
			merged = append(merged, b[j])
			j++
		}
	}
	// i < len(a) || j < len(b) == true
	if i < len(a) {
		merged = append(merged, a[i:]...)
	}
	if j < len(b) {
		merged = append(merged, b[j:]...)
	}

	return merged
}
