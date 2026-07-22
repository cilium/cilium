// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package key

import (
	"maps"
	"strings"

	"github.com/cilium/cilium/pkg/labelsfilter"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	// MetadataKeyBackendKey is the key used to store the backend key.
	MetadataKeyBackendKey = iota
)

var _ allocator.AllocatorKey = (*GlobalIdentity)(nil)

// GlobalIdentity is the structure used to store an identity
type GlobalIdentity struct {
	lbls labels.LabelArray

	// metadata contains metadata that are stored for example by the backends.
	metadata map[any]any
}

func NewGlobalIdentity(lbls labels.LabelArray) *GlobalIdentity {
	return &GlobalIdentity{
		metadata: map[any]any{},
		lbls:     lbls,
	}
}

// GetKey encodes an Identity as string
func (gi *GlobalIdentity) GetKey() string {
	var str strings.Builder
	for _, l := range gi.lbls {
		str.Write(l.FormatForKVStore())
	}
	return str.String()
}

// GetAsMap encodes a GlobalIdentity a map of keys to values. The keys will
// include a source delimted by a ':'. This output is pareable by PutKeyFromMap.
func (gi *GlobalIdentity) GetAsMap() map[string]string {
	return gi.lbls.StringMap()
}

// PutKey decodes an Identity from its string representation
func (gi *GlobalIdentity) PutKey(v string) allocator.AllocatorKey {
	return &GlobalIdentity{lbls: labels.NewLabelArrayFromSortedList(v)}
}

// PutKeyFromMap decodes an Identity from a map of key to value. Output
// from GetAsMap can be parsed.
// Note: NewLabelArrayFromMap will parse the ':' separated label source from
// the keys because the source parameter is ""
func (gi *GlobalIdentity) PutKeyFromMap(v map[string]string) allocator.AllocatorKey {
	return &GlobalIdentity{lbls: labels.Map2Labels(v, "").LabelArray()}
}

func (gi *GlobalIdentity) String() string {
	return gi.lbls.String()
}

func (gi *GlobalIdentity) LabelArray() labels.LabelArray {
	return gi.lbls
}

func (gi *GlobalIdentity) Labels() labels.Labels {
	return gi.lbls.Labels()
}

func (gi *GlobalIdentity) Equals(other *GlobalIdentity) bool {
	return gi.lbls.Equals(other.lbls)
}

// PutValue puts metadata inside the global identity for the given 'key' with
// the given 'value'.
func (gi *GlobalIdentity) PutValue(key, value any) allocator.AllocatorKey {
	newMap := map[any]any{}
	if gi.metadata != nil {
		newMap = maps.Clone(gi.metadata)
	}
	newMap[key] = value
	return &GlobalIdentity{
		lbls:     gi.lbls,
		metadata: newMap,
	}
}

// Value returns the value stored in the metadata map.
func (gi *GlobalIdentity) Value(key any) any {
	return gi.metadata[key]
}

func GetCIDKeyFromLabels(allLabels map[string]string, source string) *GlobalIdentity {
	lbs := labels.Map2Labels(allLabels, source)
	idLabels, _ := labelsfilter.Filter(lbs)
	return &GlobalIdentity{lbls: idLabels.LabelArray()}
}
