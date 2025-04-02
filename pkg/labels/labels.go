// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"bytes"
	"encoding/json"
	"iter"
	"maps"
	"slices"
	"strings"
	"unique"
	"unsafe"
)

// NOTE: Keep this file dedicated to the core implementation of Labels.
// Put the domain specific logic to labels_ext.go or label_ext.go.

// Labels is an immutable set of [Label]s.
type Labels struct {
	// handle stores uniquely small set of labels, allowing deduplication
	// and quick comparisons for majority of the label sets.
	handle unique.Handle[smallRep]

	// overflow stores very large label sets that do not all fit into the
	// smallRep. These are not unique'd. Stored as pointer to slice so that
	// we only use a pointer worth of bits instead of the full slice header.
	overflow *[]Label

	// noCompare makes the Labels struct uncomparable, which it needs to be since
	// 'overflow' pointer comparison is not meaningful. Comparisons of labels must
	// be done with 'Equal'
	_ noCompare
}

type noCompare [0]func()

var labelsCache = newCache[smallRep]()

// Empty is the canonical empty set of labels.
var Empty = NewLabels()

func NewLabels(lbls ...Label) Labels {
	// Sort the labels by key and remember if we see any duplicates
	equalKeysSeen := false
	slices.SortStableFunc(lbls, func(a, b Label) int {
		cmp := strings.Compare(a.Key(), b.Key())
		if cmp == 0 {
			equalKeysSeen = true
		}
		return cmp
	})
	if equalKeysSeen {
		// Remove the duplicates we saw during sorting. The last one
		// wins.
		lbls = compactSortedLabels(lbls)
	}
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

// compactSortedLabels removes duplicate keys. The last one wins.
func compactSortedLabels(lbls []Label) []Label {
	if len(lbls) < 2 {
		return lbls
	}

	// Iterate over the labels looking for runs of duplicates.
	// 'r' is the "read head", e.g. the label we're currently
	// looking at, and 'w' is the write head. If there are
	// duplicates 'r' will be further ahead than 'w'.
	r, w := 0, 0
	for r < len(lbls) {
		k := lbls[r].Key()

		// Find the last index 'i' where the key matches.
		i := r
		for i+1 < len(lbls) && lbls[i+1].Key() == k {
			i++
		}
		if i != r {
			// Duplicates found, write out the last one and start
			// looking at the next label with a different key.
			lbls[w] = lbls[i]
			r = i + 1
		} else {
			lbls[w] = lbls[r]
			r++
		}
		w++
	}
	clear(lbls[w:]) // zero out the tail for GC
	return lbls[:w]
}

func labelsHash(lbls []Label) (hash uint64) {
	for _, l := range lbls {
		hash ^= l.rep().hash
	}
	return
}

// isZero returns true if the labels is the zero value and thus
// invalid.
func (lbls Labels) isZero() bool {
	type h struct{ rep *smallRep }
	hp := (*h)(unsafe.Pointer(&lbls.handle))
	return hp.rep == nil
}

func (lbls Labels) rep() *smallRep {
	type h struct{ rep *smallRep }
	hp := (*h)(unsafe.Pointer(&lbls.handle))
	return hp.rep
}

func (lbls Labels) Len() int {
	if lbls.isZero() {
		return 0
	}
	length := int(lbls.handle.Value().smallLen)
	if lbls.overflow != nil {
		length += len(*lbls.overflow)
	}
	return length
}

func (lbls Labels) IsEmpty() bool {
	if lbls.isZero() {
		return true
	}
	return lbls.rep().smallLen == 0
}

func (lbls Labels) Equal(other Labels) bool {
	switch {
	case lbls.IsEmpty():
		return other.IsEmpty()
	case other.IsEmpty():
		return lbls.IsEmpty()
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

// Less returns true if [lbls] comes before [other] in the lexicographical order.
func (lbls Labels) Less(other Labels) bool {
	if lbls.IsEmpty() && other.IsEmpty() {
		return false
	}
	nextA, stopA := iter.Pull(lbls.All())
	defer stopA()
	nextB, stopB := iter.Pull(other.All())
	defer stopB()
	for {
		a, okA := nextA()
		b, okB := nextB()
		switch {
		case !okA:
			// [lbls] is less than [other] only if it is shorter.
			return okB
		case !okB:
			return false
		default:
			switch a.Compare(b) {
			case -1:
				return true
			case 1:
				return false
			}
		}
	}
}

func (lbls Labels) GetLabel(key string) (lbl Label, found bool) {
	if lbls.isZero() {
		return
	}

	lbl, found = lbls.rep().get(key)
	if !found && lbls.overflow != nil {
		// Label not found from the small array, look into the overflow array.
		idx, found := slices.BinarySearchFunc(
			*lbls.overflow,
			key,
			func(l Label, key string) int {
				return strings.Compare(l.Key(), key)
			})
		if found {
			lbl = (*lbls.overflow)[idx]
			return lbl, true
		}
	}
	return
}

func (lbls Labels) GetOrEmpty(key string) Label {
	lbl, found := lbls.GetLabel(key)
	if !found {
		lbl = EmptyLabel
	}
	return lbl
}

func (lbls Labels) GetValue(key string) string {
	lbl, found := lbls.GetLabel(key)
	if !found {
		return ""
	}
	return lbl.Value()
}

func (lbls Labels) All() iter.Seq[Label] {
	return func(yield func(Label) bool) {
		if lbls.isZero() {
			return
		}
		rep := lbls.rep()
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

// smallLabelsSize is the number of labels to store in the "small" array.
// The value is derived from tests on a large real-world data set when
// optimizing for smallest memory use.
const smallLabelsSize = 9

func (lbls Labels) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteRune('[')
	remaining := lbls.Len()
	for l := range lbls.All() {
		lb, err := l.MarshalJSON()
		if err != nil {
			return nil, err
		}
		buf.Write(lb)
		remaining--
		if remaining > 0 {
			buf.WriteRune(',')
		}
	}
	buf.WriteRune(']')
	return buf.Bytes(), nil
}

func (lbls *Labels) UnmarshalJSON(b []byte) error {
	// Unmarshalling the labels is not as much on the critical path
	// as marshalling as it's mostly done when restoring endpoints.
	// Hence we're just doing the straightforward thing and unmarshalling
	// into a map first.
	var ls []Label
	if err := json.Unmarshal(b, &ls); err != nil {
		// Fall back to unmarshalling from a map.
		var m map[string]Label
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		ls = slices.AppendSeq(make([]Label, 0, len(m)), maps.Values(m))
	}
	if len(ls) == 0 {
		*lbls = Labels{}
	} else {
		*lbls = NewLabels(ls...)
	}
	return nil
}

// smallRep is the internal unique'd representation for a small set of labels.
// The labels are stored sorted by key.
type smallRep struct {
	// smallArray stores small set of labels. This reduces heap allocations
	// and fragmentation for small label sets.
	smallArray [smallLabelsSize]Label

	// smallLen is the number of labels in 'smallArray'
	smallLen uint8
}

func (rep *smallRep) get(key string) (lbl Label, found bool) {
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
