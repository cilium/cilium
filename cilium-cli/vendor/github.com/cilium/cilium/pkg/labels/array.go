// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
			if ls[l].Has(&needed[i]) {
				continue nextLabel
			}
		}

		return false
	}

	return true
}

// Intersects returns true if ls contains at least one label in needed.
//
// This has the same matching semantics as Has, namely,
// ["k8s:foo=bar"].Intersects(["any:foo=bar"]) == true
// ["any:foo=bar"].Intersects(["k8s:foo=bar"]) == false
func (ls LabelArray) Intersects(needed LabelArray) bool {
	for _, l := range ls {
		for _, n := range needed {
			if l.Has(&n) {
				return true
			}
		}
	}
	return false
}

// Lacks is identical to Contains but returns all missing labels
func (ls LabelArray) Lacks(needed LabelArray) LabelArray {
	missing := LabelArray{}
nextLabel:
	for i := range needed {
		for l := range ls {
			if ls[l].Has(&needed[l]) {
				continue nextLabel
			}
		}

		missing = append(missing, needed[i])
	}

	return missing
}

// Has returns whether the provided key exists in the label array.
// Implementation of the
// github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels.Labels interface.
//
// The key can be of source "any", in which case the source is
// ignored. The inverse, however, is not true.
// ["k8s.foo=bar"].Has("any.foo") => true
// ["any.foo=bar"].Has("k8s.foo") => false
//
// If the key is of source "cidr", this will also match
// broader keys.
// ["cidr:1.1.1.1/32"].Has("cidr.1.0.0.0/8") => true
// ["cidr:1.0.0.0/8"].Has("cidr.1.1.1.1/32") => false
func (ls LabelArray) Has(key string) bool {
	// The key is submitted in the form of `source.key=value`
	keyLabel := parseSelectLabel(key, '.')
	for _, l := range ls {
		if l.HasKey(&keyLabel) {
			return true
		}
	}
	return false
}

// Get returns the value for the provided key.
// Implementation of the
// github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels.Labels interface.
//
// The key can be of source "any", in which case the source is
// ignored. The inverse, however, is not true.
// ["k8s.foo=bar"].Get("any.foo") => "bar"
// ["any.foo=bar"].Get("k8s.foo") => ""
//
// If the key is of source "cidr", this will also match
// broader keys.
// ["cidr:1.1.1.1/32"].Has("cidr.1.0.0.0/8") => true
// ["cidr:1.0.0.0/8"].Has("cidr.1.1.1.1/32") => false
func (ls LabelArray) Get(key string) string {
	keyLabel := parseSelectLabel(key, '.')
	for _, l := range ls {
		if l.HasKey(&keyLabel) {
			return l.Value
		}
	}
	return ""
}

// DeepCopy returns a deep copy of the labels.
func (ls LabelArray) DeepCopy() LabelArray {
	if ls == nil {
		return nil
	}

	o := make(LabelArray, len(ls))
	copy(o, ls)
	return o
}

// GetModel returns the LabelArray as a string array with fully-qualified labels.
// The output is parseable by ParseLabelArrayFromArray
func (ls LabelArray) GetModel() []string {
	res := make([]string, 0, len(ls))
	for l := range ls {
		res = append(res, ls[l].String())
	}
	return res
}

func (ls LabelArray) String() string {
	var sb strings.Builder
	sb.WriteString("[")
	for l := range ls {
		if l > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(ls[l].String())
	}
	sb.WriteString("]")
	return sb.String()
}

// StringMap converts LabelArray into map[string]string
// Note: The source is included in the keys with a ':' separator.
// Note: LabelArray does not deduplicate entries, as it is an array. It is
// possible for the output to contain fewer entries when the source and key are
// repeated in a LabelArray, as that is the key of the output. This scenario is
// not expected.
func (ls LabelArray) StringMap() map[string]string {
	o := map[string]string{}
	for _, v := range ls {
		o[v.Source+":"+v.Key] = v.Value
	}
	return o
}

// Equals returns true if the label arrays are the same, i.e., have the same labels in the same order.
func (ls LabelArray) Equals(b LabelArray) bool {
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

// Less returns true if ls comes before b in the lexicographical order.
// Assumes both ls and b are already sorted.
func (ls LabelArray) Less(b LabelArray) bool {
	lsLen, bLen := len(ls), len(b)

	minLen := lsLen
	if bLen < minLen {
		minLen = bLen
	}

	for i := 0; i < minLen; i++ {
		switch {
		// Key
		case ls[i].Key < b[i].Key:
			return true
		case ls[i].Key > b[i].Key:
			return false
		// Value
		case ls[i].Value < b[i].Value:
			return true
		case ls[i].Value > b[i].Value:
			return false
		// Source
		case ls[i].Source < b[i].Source:
			return true
		case ls[i].Source > b[i].Source:
			return false
		}
	}

	return lsLen < bLen
}
