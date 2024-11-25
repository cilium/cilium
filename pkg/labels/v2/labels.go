// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"iter"
	"slices"
	"strings"
	"unique"
)

// NOTE: Keep this file dedicated to the core implementation of Labels.
// Put the domain specific logic to labels_ext.go or label_ext.go.

type Labels struct {
	// handle stores uniquely small set of labels, allowing deduplication
	// and quick comparisons for majority of the label sets.
	handle unique.Handle[smallRep]

	// overflow stores very large label sets that do not all fit into the
	// smallRep. These are not unique'd. Stored as pointer to slice so that
	// we only use a pointer worth of bits instead of the full slice header.
	overflow *[]Label
}

var labelsCache = newCache[smallRep]()

func NewLabels(lbls ...Label) Labels {
	// Sort the labels by key
	slices.SortFunc(lbls, func(a, b Label) int {
		return strings.Compare(a.Key(), b.Key())
	})
	smallArrayLabels := lbls[:min(len(lbls), smallLabelsSize)]

	// Lookup or create the unique handle to the small array of labels.
	var labels Labels
	labels.handle = labelsCache.lookupOrMake(
		labelsHash(smallArrayLabels),
		func(other smallRep) bool {
			return slices.Equal(smallArrayLabels, other.smallArray[:other.smallLen])
		},
		func(hash uint64) (rep smallRep) {
			rep.smallLen = uint8(copy(rep.smallArray[:], smallArrayLabels))
			return
		},
	)
	if len(lbls) > smallLabelsSize {
		overflowLabels := lbls[len(smallArrayLabels):]
		labels.overflow = &overflowLabels
	}
	return labels
}

func labelsHash(lbls []Label) (hash uint64) {
	for _, l := range lbls {
		hash ^= l.rep().hash
	}
	return
}

// Map2Labels transforms in the form: map[key(string)]value(string) into Labels. The
// source argument will overwrite the source written in the key of the given map.
// Example:
// l := Map2Labels(map[string]string{"k8s:foo": "bar"}, "cilium")
// l == [{Key: "foo", Value: "bar", Source: "cilium")]
func Map2Labels(m map[string]string, source string) Labels {
	if len(m) <= smallLabelsSize {
		// Fast path: fits into the small array and we can sort in-place.
		rep := smallRep{}
		for k, v := range m {
			rep.smallArray[rep.smallLen] = NewLabel(k, v, source)
			rep.smallLen++
		}
		slices.SortFunc(rep.smallArray[:rep.smallLen], func(a, b Label) int {
			return strings.Compare(a.Key(), b.Key())
		})
		return Labels{
			handle: unique.Make(rep),
		}
	}

	// Slow path: does not fit into small array. Build up an temporary,
	// sort it, and construct the labels with it.
	lbls := make([]Label, 0, len(m))
	for k, v := range m {
		lbls = append(lbls, NewLabel(k, v, source))
	}
	return NewLabels(lbls...)
}

func (lbls Labels) StringMap() (m map[string]string) {
	m = make(map[string]string, lbls.Len())
	for l := range lbls.All() {
		rep := l.rep()
		// Key is "Source:Key", which is what we already have in skv.
		m[rep.skv[:rep.vpos-1]] = rep.value()
	}
	return
}

func (lbls Labels) Len() int {
	length := int(lbls.handle.Value().smallLen)
	if lbls.overflow != nil {
		length += len(*lbls.overflow)
	}
	return length
}

func (lbls Labels) Equal(other Labels) bool {
	switch {
	case lbls.overflow == nil && other.overflow == nil:
		// No overflow, can compare handles directly.
		return lbls.handle == other.handle
	case lbls.overflow != nil && other.overflow != nil:
		return lbls.handle == other.handle &&
			slices.EqualFunc(*lbls.overflow, *other.overflow, Label.Equal)
	default:
		return false
	}
}

func (lbls Labels) Get(key string) (lbl Label, found bool) {
	lbl, found = lbls.handle.Value().get(key)
	if !found && lbls.overflow != nil {
		// Label not found from the small array, look into the overflow array.
		idx, found := slices.BinarySearchFunc(
			*lbls.overflow,
			key,
			func(l Label, key string) int {
				return strings.Compare(l.Key(), key)
			})
		if found {
			return (*lbls.overflow)[idx], true
		}
	}
	return
}

func (lbls Labels) All() iter.Seq[Label] {
	return func(yield func(Label) bool) {
		rep := lbls.handle.Value()
		for _, l := range rep.smallArray[:rep.smallLen] {
			if !yield(l) {
				return
			}
		}
		if lbls.overflow != nil {
			for _, l := range *lbls.overflow {
				if !yield(l) {
					return
				}
			}
		}
	}
}

func (lbls Labels) String() string {
	var b strings.Builder
	for l := range lbls.All() {
		b.WriteString(l.String())
		b.WriteByte(',')
	}
	s := b.String()
	if len(s) > 0 {
		// Drop trailing comma
		s = s[:len(s)-1]
	}
	return s
}

const smallLabelsSize = 7 // 7*8+1 < 64 => fits in cache line

// smallRep is the internal unique'd representation for a small set of labels.
// The labels are stored sorted by key.
type smallRep struct {
	// smallArray stores small set of labels. This reduces heap allocations
	// and fragmentation for small label sets.
	smallArray [smallLabelsSize]Label

	// smallLen is the number of labels in 'smallArray'
	smallLen uint8
}

func (rep smallRep) get(key string) (lbl Label, found bool) {
	for i := 0; i < int(rep.smallLen); i++ {
		candidate := rep.smallArray[i]
		switch strings.Compare(candidate.Key(), key) {
		case -1:
			continue
		case 0:
			return candidate, true
		default:
			return
		}
	}
	return
}
