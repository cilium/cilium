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

// GlobalIdentity is the structure used to store an identity
type GlobalIdentity struct {
	labels labels.LabelArray

	// metadata contains metadata that are stored for example by the backends.
	metadata map[any]any
}

func MakeGlobalIdentity(labels labels.LabelArray) *GlobalIdentity {
	return &GlobalIdentity{
		labels: labels,
	}
}

func (gi *GlobalIdentity) Labels() labels.LabelArray {
	return gi.labels
}

// GetKey encodes an Identity as string
func (gi *GlobalIdentity) GetKey() string {
	var str strings.Builder
	for _, l := range gi.labels {
		str.Write(l.FormatForKVStore())
	}
	return str.String()
}

func (gi *GlobalIdentity) String() string {
	return gi.labels.String()
}

// Equals compares keys without comparing metadata.
func (gi *GlobalIdentity) Equals(i *GlobalIdentity) bool {
	return gi.labels.Equals(i.labels)
}

// GetAsMap encodes a GlobalIdentity a map of keys to values. The keys will
// include a source delimted by a ':'. This output is pareable by PutKeyFromMap.
func (gi *GlobalIdentity) GetAsMap() map[string]string {
	return gi.labels.StringMap()
}

// PutKey decodes an Identity from its string representation.
// This allocates a new identity.
func (gi *GlobalIdentity) PutKey(v string) allocator.AllocatorKey {
	return MakeGlobalIdentity(labels.NewLabelArrayFromSortedList(v))
}

// PutKeyFromMap decodes an Identity from a map of key to value. Output
// from GetAsMap can be parsed.
// Note: NewLabelArrayFromMap will parse the ':' separated label source from
// the keys because the source parameter is ""
func (gi *GlobalIdentity) PutKeyFromMap(v map[string]string) allocator.AllocatorKey {
	return MakeGlobalIdentity(labels.Map2Labels(v, "").LabelArray())
}

// PutValue puts metadata inside the global identity for the given 'key' with
// the given 'value'.
// Returns a copy.
func (gi *GlobalIdentity) PutValue(key, value any) allocator.AllocatorKey {
	newMap := map[any]any{}
	if gi.metadata != nil {
		newMap = maps.Clone(gi.metadata)
	}
	newMap[key] = value
	return &GlobalIdentity{
		labels:   gi.labels,
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
	return MakeGlobalIdentity(idLabels.LabelArray())
}
