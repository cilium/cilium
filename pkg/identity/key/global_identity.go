// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package key

import (
	"strings"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/labels"
)

// GlobalIdentity is the structure used to store an identity
type GlobalIdentity struct {
	labels.LabelArray
}

// GetKey encodes an Identity as string
func (gi *GlobalIdentity) GetKey() string {
	var str strings.Builder
	for _, l := range gi.LabelArray {
		str.Write(l.FormatForKVStore())
	}
	return str.String()
}

// GetAsMap encodes a GlobalIdentity a map of keys to values. The keys will
// include a source delimted by a ':'. This output is pareable by PutKeyFromMap.
func (gi *GlobalIdentity) GetAsMap() map[string]string {
	return gi.StringMap()
}

// PutKey decodes an Identity from its string representation
func (gi *GlobalIdentity) PutKey(v string) allocator.AllocatorKey {
	return &GlobalIdentity{labels.NewLabelArrayFromSortedList(v)}
}

// PutKeyFromMap decodes an Identity from a map of key to value. Output
// from GetAsMap can be parsed.
// Note: NewLabelArrayFromMap will parse the ':' separated label source from
// the keys because the source parameter is ""
func (gi *GlobalIdentity) PutKeyFromMap(v map[string]string) allocator.AllocatorKey {
	return &GlobalIdentity{labels.Map2Labels(v, "").LabelArray()}
}
