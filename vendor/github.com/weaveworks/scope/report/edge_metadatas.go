package report

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"reflect"
	"sort"
	"strconv"

	"github.com/ugorji/go/codec"
	"github.com/weaveworks/ps"
)

// EdgeMetadatas collect metadata about each edge in a topology. Keys are the
// remote node IDs, as in Adjacency.
type EdgeMetadatas struct {
	psMap ps.Map
}

// EmptyEdgeMetadatas is the set of empty EdgeMetadatas.
var EmptyEdgeMetadatas = EdgeMetadatas{ps.NewMap()}

// MakeEdgeMetadatas returns EmptyEdgeMetadatas
func MakeEdgeMetadatas() EdgeMetadatas {
	return EmptyEdgeMetadatas
}

// Copy is a noop
func (c EdgeMetadatas) Copy() EdgeMetadatas {
	return c
}

// Add value to the counter 'key'
func (c EdgeMetadatas) Add(key string, value EdgeMetadata) EdgeMetadatas {
	if c.psMap == nil {
		c = EmptyEdgeMetadatas
	}
	if existingValue, ok := c.psMap.Lookup(key); ok {
		value = value.Merge(existingValue.(EdgeMetadata))
	}
	return EdgeMetadatas{
		c.psMap.Set(key, value),
	}
}

// Lookup the counter 'key'
func (c EdgeMetadatas) Lookup(key string) (EdgeMetadata, bool) {
	if c.psMap != nil {
		existingValue, ok := c.psMap.Lookup(key)
		if ok {
			return existingValue.(EdgeMetadata), true
		}
	}
	return EdgeMetadata{}, false
}

// Size is the number of elements
func (c EdgeMetadatas) Size() int {
	if c.psMap == nil {
		return 0
	}
	return c.psMap.Size()
}

// Merge produces a fresh Counters, container the keys from both inputs. When
// both inputs container the same key, the latter value is used.
func (c EdgeMetadatas) Merge(other EdgeMetadatas) EdgeMetadatas {
	var (
		cSize     = c.Size()
		otherSize = other.Size()
		output    = c.psMap
		iter      = other.psMap
	)
	switch {
	case cSize == 0:
		return other
	case otherSize == 0:
		return c
	case cSize < otherSize:
		output, iter = iter, output
	}
	iter.ForEach(func(key string, otherVal interface{}) {
		if val, ok := output.Lookup(key); ok {
			output = output.Set(key, otherVal.(EdgeMetadata).Merge(val.(EdgeMetadata)))
		} else {
			output = output.Set(key, otherVal)
		}
	})
	return EdgeMetadatas{output}
}

// Flatten flattens all the EdgeMetadatas in this set and returns the result.
// The original is not modified.
func (c EdgeMetadatas) Flatten() EdgeMetadata {
	result := EdgeMetadata{}
	c.ForEach(func(_ string, e EdgeMetadata) {
		result = result.Flatten(e)
	})
	return result
}

// ForEach executes f on each key value pair in the map
func (c EdgeMetadatas) ForEach(fn func(k string, v EdgeMetadata)) {
	if c.psMap != nil {
		c.psMap.ForEach(func(key string, value interface{}) {
			fn(key, value.(EdgeMetadata))
		})
	}
}

func (c EdgeMetadatas) String() string {
	keys := []string{}
	if c.psMap == nil {
		c = EmptyEdgeMetadatas
	}
	for _, k := range c.psMap.Keys() {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := bytes.NewBufferString("{")
	for _, key := range keys {
		val, _ := c.psMap.Lookup(key)
		fmt.Fprintf(buf, "%s: %v, ", key, val)
	}
	fmt.Fprintf(buf, "}")
	return buf.String()
}

// DeepEqual tests equality with other Counters
func (c EdgeMetadatas) DeepEqual(d EdgeMetadatas) bool {
	if c.Size() != d.Size() {
		return false
	}
	if c.Size() == 0 {
		return true
	}

	equal := true
	c.psMap.ForEach(func(k string, val interface{}) {
		if otherValue, ok := d.psMap.Lookup(k); !ok {
			equal = false
		} else {
			equal = equal && reflect.DeepEqual(val, otherValue)
		}
	})
	return equal
}

func (c EdgeMetadatas) toIntermediate() map[string]EdgeMetadata {
	intermediate := map[string]EdgeMetadata{}
	if c.psMap != nil {
		c.psMap.ForEach(func(key string, val interface{}) {
			intermediate[key] = val.(EdgeMetadata)
		})
	}
	return intermediate
}

func (c EdgeMetadatas) fromIntermediate(in map[string]EdgeMetadata) EdgeMetadatas {
	out := ps.NewMap()
	for k, v := range in {
		out = out.Set(k, v)
	}
	return EdgeMetadatas{out}
}

// CodecEncodeSelf implements codec.Selfer
func (c *EdgeMetadatas) CodecEncodeSelf(encoder *codec.Encoder) {
	if c.psMap != nil {
		encoder.Encode(c.toIntermediate())
	} else {
		encoder.Encode(nil)
	}
}

// CodecDecodeSelf implements codec.Selfer
func (c *EdgeMetadatas) CodecDecodeSelf(decoder *codec.Decoder) {
	in := map[string]EdgeMetadata{}
	if err := decoder.Decode(&in); err != nil {
		return
	}
	*c = EdgeMetadatas{}.fromIntermediate(in)
}

// MarshalJSON shouldn't be used, use CodecEncodeSelf instead
func (EdgeMetadatas) MarshalJSON() ([]byte, error) {
	panic("MarshalJSON shouldn't be used, use CodecEncodeSelf instead")
}

// UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead
func (*EdgeMetadatas) UnmarshalJSON(b []byte) error {
	panic("UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead")
}

// GobEncode implements gob.Marshaller
func (c EdgeMetadatas) GobEncode() ([]byte, error) {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(c.toIntermediate())
	return buf.Bytes(), err
}

// GobDecode implements gob.Unmarshaller
func (c *EdgeMetadatas) GobDecode(input []byte) error {
	in := map[string]EdgeMetadata{}
	if err := gob.NewDecoder(bytes.NewBuffer(input)).Decode(&in); err != nil {
		return err
	}
	*c = EdgeMetadatas{}.fromIntermediate(in)
	return nil
}

// EdgeMetadata describes a superset of the metadata that probes can possibly
// collect about a directed edge between two nodes in any topology.
type EdgeMetadata struct {
	EgressPacketCount  *uint64 `json:"egress_packet_count,omitempty"`
	IngressPacketCount *uint64 `json:"ingress_packet_count,omitempty"`
	EgressByteCount    *uint64 `json:"egress_byte_count,omitempty"`  // Transport layer
	IngressByteCount   *uint64 `json:"ingress_byte_count,omitempty"` // Transport layer
}

// String returns a string representation of this EdgeMetadata
// Helps with our use of Spew and diff.
func (e EdgeMetadata) String() string {
	f := func(i *uint64) string {
		if i == nil {
			return "nil"
		}
		return strconv.FormatUint(*i, 10)
	}

	return fmt.Sprintf(`{
EgressPacketCount:  %v,
IngressPacketCount: %v,
EgressByteCount:    %v,
IngressByteCount:   %v,
}`,
		f(e.EgressPacketCount),
		f(e.IngressPacketCount),
		f(e.EgressByteCount),
		f(e.IngressByteCount))
}

// Copy returns a value copy of the EdgeMetadata.
func (e EdgeMetadata) Copy() EdgeMetadata {
	return EdgeMetadata{
		EgressPacketCount:  cpu64ptr(e.EgressPacketCount),
		IngressPacketCount: cpu64ptr(e.IngressPacketCount),
		EgressByteCount:    cpu64ptr(e.EgressByteCount),
		IngressByteCount:   cpu64ptr(e.IngressByteCount),
	}
}

// Reversed returns a value copy of the EdgeMetadata, with the direction reversed.
func (e EdgeMetadata) Reversed() EdgeMetadata {
	return EdgeMetadata{
		EgressPacketCount:  cpu64ptr(e.IngressPacketCount),
		IngressPacketCount: cpu64ptr(e.EgressPacketCount),
		EgressByteCount:    cpu64ptr(e.IngressByteCount),
		IngressByteCount:   cpu64ptr(e.EgressByteCount),
	}
}

func cpu64ptr(u *uint64) *uint64 {
	if u == nil {
		return nil
	}
	value := *u   // oh man
	return &value // this sucks
}

// Merge merges another EdgeMetadata into the receiver and returns the result.
// The receiver is not modified. The two edge metadatas should represent the
// same edge on different times.
func (e EdgeMetadata) Merge(other EdgeMetadata) EdgeMetadata {
	cp := e.Copy()
	cp.EgressPacketCount = merge(cp.EgressPacketCount, other.EgressPacketCount, sum)
	cp.IngressPacketCount = merge(cp.IngressPacketCount, other.IngressPacketCount, sum)
	cp.EgressByteCount = merge(cp.EgressByteCount, other.EgressByteCount, sum)
	cp.IngressByteCount = merge(cp.IngressByteCount, other.IngressByteCount, sum)
	return cp
}

// Flatten sums two EdgeMetadatas and returns the result. The receiver is not
// modified. The two edge metadata windows should be the same duration; they
// should represent different edges at the same time.
func (e EdgeMetadata) Flatten(other EdgeMetadata) EdgeMetadata {
	cp := e.Copy()
	cp.EgressPacketCount = merge(cp.EgressPacketCount, other.EgressPacketCount, sum)
	cp.IngressPacketCount = merge(cp.IngressPacketCount, other.IngressPacketCount, sum)
	cp.EgressByteCount = merge(cp.EgressByteCount, other.EgressByteCount, sum)
	cp.IngressByteCount = merge(cp.IngressByteCount, other.IngressByteCount, sum)
	return cp
}

func merge(dst, src *uint64, op func(uint64, uint64) uint64) *uint64 {
	if src == nil {
		return dst
	}
	if dst == nil {
		dst = new(uint64)
	}
	(*dst) = op(*dst, *src)
	return dst
}

func sum(dst, src uint64) uint64 {
	return dst + src
}

func max(dst, src uint64) uint64 {
	if dst > src {
		return dst
	}
	return src
}
