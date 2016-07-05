package report

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/ugorji/go/codec"
	"github.com/weaveworks/ps"
)

// LatestEntryDecoder is an interface for decoding the LatestEntry instances.
type LatestEntryDecoder interface {
	Decode(decoder *codec.Decoder, entry *LatestEntry)
}

// LatestMap is a persistent map which support latest-win merges. We
// have to embed ps.Map as its interface. LatestMaps are immutable.
type LatestMap struct {
	ps.Map
	decoder LatestEntryDecoder
}

// LatestEntry represents a timestamped value inside the LatestMap.
type LatestEntry struct {
	Timestamp time.Time   `json:"timestamp"`
	Value     interface{} `json:"value"`
}

// String returns the LatestEntry's string representation.
func (e LatestEntry) String() string {
	return fmt.Sprintf("%v (%s)", e.Value, e.Timestamp.String())
}

// Equal returns true if the supplied LatestEntry is equal to this one.
func (e LatestEntry) Equal(e2 LatestEntry) bool {
	return e.Timestamp.Equal(e2.Timestamp) && e.Value == e2.Value
}

// MakeLatestMapWithDecoder makes an empty LatestMap holding custom values.
func MakeLatestMapWithDecoder(decoder LatestEntryDecoder) LatestMap {
	return LatestMap{ps.NewMap(), decoder}
}

// Copy is a noop, as LatestMaps are immutable.
func (m LatestMap) Copy() LatestMap {
	return m
}

// Size returns the number of elements.
func (m LatestMap) Size() int {
	if m.Map == nil {
		return 0
	}
	return m.Map.Size()
}

// Merge produces a fresh StringLatestMap containing the keys from
// both inputs. When both inputs contain the same key, the newer value
// is used.
func (m LatestMap) Merge(other LatestMap) LatestMap {
	var (
		mSize     = m.Size()
		otherSize = other.Size()
		output    = m.Map
		iter      = other.Map
	)
	switch {
	case mSize == 0:
		return other
	case otherSize == 0:
		return m
	case mSize < otherSize:
		output, iter = iter, output
	}
	if m.decoder != other.decoder {
		panic(fmt.Sprintf("Cannot merge maps with different entry value types, this has %#v, other has %#v", m.decoder, other.decoder))
	}

	iter.ForEach(func(key string, iterVal interface{}) {
		if existingVal, ok := output.Lookup(key); ok {
			if existingVal.(LatestEntry).Timestamp.Before(iterVal.(LatestEntry).Timestamp) {
				output = output.Set(key, iterVal)
			}
		} else {
			output = output.Set(key, iterVal)
		}
	})

	return LatestMap{output, m.decoder}
}

// Lookup the value for the given key.
func (m LatestMap) Lookup(key string) (interface{}, bool) {
	v, _, ok := m.LookupEntry(key)
	return v, ok
}

// LookupEntry returns the raw entry for the given key.
func (m LatestMap) LookupEntry(key string) (interface{}, time.Time, bool) {
	if m.Map == nil {
		return nil, time.Time{}, false
	}
	value, ok := m.Map.Lookup(key)
	if !ok {
		return nil, time.Time{}, false
	}
	e := value.(LatestEntry)
	return e.Value, e.Timestamp, true
}

// Set sets the value for the given key.
func (m LatestMap) Set(key string, timestamp time.Time, value interface{}) LatestMap {
	if m.Map == nil {
		m = MakeLatestMapWithDecoder(m.decoder)
	}
	return LatestMap{m.Map.Set(key, LatestEntry{timestamp, value}), m.decoder}
}

// Delete the value for the given key.
func (m LatestMap) Delete(key string) LatestMap {
	if m.Map == nil {
		m = MakeLatestMapWithDecoder(m.decoder)
	}
	return LatestMap{m.Map.Delete(key), m.decoder}
}

// ForEach executes fn on each key, timestamp, value triple in the map.
func (m LatestMap) ForEach(fn func(k string, ts time.Time, v interface{})) {
	if m.Map == nil {
		return
	}
	m.Map.ForEach(func(key string, value interface{}) {
		fn(key, value.(LatestEntry).Timestamp, value.(LatestEntry).Value)
	})
}

// String returns the LatestMap's string representation.
func (m LatestMap) String() string {
	keys := []string{}
	if m.Map == nil {
		m = MakeLatestMapWithDecoder(m.decoder)
	}
	for _, k := range m.Map.Keys() {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := bytes.NewBufferString("{")
	for _, key := range keys {
		val, _ := m.Map.Lookup(key)
		fmt.Fprintf(buf, "%s: %s,\n", key, val)
	}
	fmt.Fprintf(buf, "}")
	return buf.String()
}

// DeepEqual tests equality with other LatestMap.
func (m LatestMap) DeepEqual(n LatestMap) bool {
	if m.Size() != n.Size() {
		return false
	}
	if m.Size() == 0 {
		return true
	}
	if m.decoder != n.decoder {
		panic(fmt.Sprintf("Cannot check equality of maps with different entry value types, this has %#v, other has %#v", m.decoder, n.decoder))
	}
	equal := true
	m.Map.ForEach(func(k string, val interface{}) {
		if otherValue, ok := n.Map.Lookup(k); !ok {
			equal = false
		} else {
			equal = equal && val.(LatestEntry).Equal(otherValue.(LatestEntry))
		}
	})
	return equal
}

func (m LatestMap) toIntermediate() map[string]LatestEntry {
	intermediate := make(map[string]LatestEntry, m.Size())
	if m.Map != nil {
		m.Map.ForEach(func(key string, val interface{}) {
			intermediate[key] = val.(LatestEntry)
		})
	}
	return intermediate
}

// CodecEncodeSelf implements codec.Selfer.
func (m *LatestMap) CodecEncodeSelf(encoder *codec.Encoder) {
	if m.Map != nil {
		encoder.Encode(m.toIntermediate())
	} else {
		encoder.Encode(nil)
	}
}

// constants from https://github.com/ugorji/go/blob/master/codec/helper.go#L207
const (
	containerMapKey   = 2
	containerMapValue = 3
	containerMapEnd   = 4
)

// CodecDecodeSelf implements codec.Selfer.
// This implementation does not use the intermediate form as that was a
// performance issue; skipping it saved almost 10% CPU.  Note this means
// we are using undocumented, internal APIs, which could break in the future.
// See https://github.com/weaveworks/scope/pull/1709 for more information.
func (m *LatestMap) CodecDecodeSelf(decoder *codec.Decoder) {
	z, r := codec.GenHelperDecoder(decoder)
	if r.TryDecodeAsNil() {
		*m = MakeLatestMapWithDecoder(m.decoder)
		return
	}

	length := r.ReadMapStart()
	out := ps.NewMap()
	for i := 0; length < 0 || i < length; i++ {
		if length < 0 && r.CheckBreak() {
			break
		}

		var key string
		z.DecSendContainerState(containerMapKey)
		if !r.TryDecodeAsNil() {
			key = r.DecodeString()
		}

		var value LatestEntry
		z.DecSendContainerState(containerMapValue)
		if !r.TryDecodeAsNil() {
			m.decoder.Decode(decoder, &value)
		}

		out = out.UnsafeMutableSet(key, value)
	}
	z.DecSendContainerState(containerMapEnd)
	*m = LatestMap{out, m.decoder}
}

// MarshalJSON shouldn't be used, use CodecEncodeSelf instead.
func (LatestMap) MarshalJSON() ([]byte, error) {
	panic("MarshalJSON shouldn't be used, use CodecEncodeSelf instead")
}

// UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead.
func (*LatestMap) UnmarshalJSON(b []byte) error {
	panic("UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead")
}
