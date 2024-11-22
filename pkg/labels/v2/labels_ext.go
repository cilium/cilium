// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"iter"
)

// This file contains the domain specific getters for 'Labels'. This
// way the core implementation is cleanly separated, while still
// having the convenience of these methods as part of 'Labels'.

func (lbls Labels) HasLabelWithKey(key string) bool {
	_, ok := lbls.Get(key)
	return ok
}

func (lbls Labels) FromSource(source string) iter.Seq[Label] {
	return func(yield func(Label) bool) {
		for l := range lbls.All() {
			if l.Source() == source {
				if !yield(l) {
					break
				}
			}
		}
	}
}

func (lbls Labels) Contains(other Labels) bool {
	rep := lbls.handle.Value()
	repOther := lbls.handle.Value()
	if lbls.overflow == nil && other.overflow == nil && rep.smallLen == repOther.smallLen {
		// Fast path, no overflow and same amount of labels. We can just compare the
		// handles directly.
		return lbls.handle == other.handle
	} else if other.Len() > lbls.Len() {
		return false
	}

	for l := range other.All() {
		_, found := lbls.Get(l.Key())
		if !found {
			return false
		}
	}
	return true
}
