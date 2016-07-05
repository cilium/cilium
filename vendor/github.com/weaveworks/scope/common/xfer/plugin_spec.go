package xfer

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sort"

	"github.com/davecgh/go-spew/spew"
	"github.com/ugorji/go/codec"
	"github.com/weaveworks/ps"

	"github.com/weaveworks/scope/test/reflect"
)

// PluginSpec is shared between the Probe, App, and UI. It is the plugin's
// self-proclaimed description.
type PluginSpec struct {
	ID string `json:"id"`

	// Label is a human-readable name of the plugin
	Label string `json:"label"`

	Description string `json:"description,omitempty"`

	// Interfaces is a list of things this plugin can be used for (e.g. "reporter")
	Interfaces []string `json:"interfaces"`

	APIVersion string `json:"api_version,omitempty"`

	Status string `json:"status,omitempty"`
}

// PluginSpecs is a set of plugin specs keyed on ID. Clients must use
// the Add method to add plugin specs
type PluginSpecs struct {
	psMap ps.Map
}

// EmptyPluginSpecs is the empty set of plugin specs.
var EmptyPluginSpecs = PluginSpecs{ps.NewMap()}

// MakePluginSpecs makes a new PluginSpecs with the given plugin specs.
func MakePluginSpecs(specs ...PluginSpec) PluginSpecs {
	return EmptyPluginSpecs.Add(specs...)
}

// Add adds the specs to the PluginSpecs. Add is the only valid way to grow a
// PluginSpecs. Add returns the PluginSpecs to enable chaining.
func (n PluginSpecs) Add(specs ...PluginSpec) PluginSpecs {
	result := n.psMap
	if result == nil {
		result = ps.NewMap()
	}
	for _, spec := range specs {
		result = result.Set(spec.ID, spec)
	}
	return PluginSpecs{result}
}

// Merge combines the two PluginSpecss and returns a new result.
func (n PluginSpecs) Merge(other PluginSpecs) PluginSpecs {
	nSize, otherSize := n.Size(), other.Size()
	if nSize == 0 {
		return other
	}
	if otherSize == 0 {
		return n
	}
	result, iter := n.psMap, other.psMap
	if nSize < otherSize {
		result, iter = iter, result
	}
	iter.ForEach(func(key string, otherVal interface{}) {
		result = result.Set(key, otherVal)
	})
	return PluginSpecs{result}
}

// Lookup the spec by 'key'
func (n PluginSpecs) Lookup(key string) (PluginSpec, bool) {
	if n.psMap != nil {
		value, ok := n.psMap.Lookup(key)
		if ok {
			return value.(PluginSpec), true
		}
	}
	return PluginSpec{}, false
}

// Keys is a list of all the keys in this set.
func (n PluginSpecs) Keys() []string {
	if n.psMap == nil {
		return nil
	}
	k := n.psMap.Keys()
	sort.Strings(k)
	return k
}

// Size is the number of specs in the set
func (n PluginSpecs) Size() int {
	if n.psMap == nil {
		return 0
	}
	return n.psMap.Size()
}

// ForEach executes f for each spec in the set. Nodes are traversed in sorted
// order.
func (n PluginSpecs) ForEach(f func(PluginSpec)) {
	for _, key := range n.Keys() {
		if val, ok := n.psMap.Lookup(key); ok {
			f(val.(PluginSpec))
		}
	}
}

// Copy is a noop
func (n PluginSpecs) Copy() PluginSpecs {
	return n
}

func (n PluginSpecs) String() string {
	keys := []string{}
	if n.psMap == nil {
		n = EmptyPluginSpecs
	}
	psMap := n.psMap
	if psMap == nil {
		psMap = ps.NewMap()
	}
	for _, k := range psMap.Keys() {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := bytes.NewBufferString("{")
	for _, key := range keys {
		val, _ := psMap.Lookup(key)
		fmt.Fprintf(buf, "%s: %s, ", key, spew.Sdump(val))
	}
	fmt.Fprintf(buf, "}")
	return buf.String()
}

// DeepEqual tests equality with other PluginSpecss
func (n PluginSpecs) DeepEqual(i interface{}) bool {
	d, ok := i.(PluginSpecs)
	if !ok {
		return false
	}

	if n.Size() != d.Size() {
		return false
	}
	if n.Size() == 0 {
		return true
	}

	equal := true
	n.psMap.ForEach(func(k string, val interface{}) {
		if otherValue, ok := d.psMap.Lookup(k); !ok {
			equal = false
		} else {
			equal = equal && reflect.DeepEqual(val, otherValue)
		}
	})
	return equal
}

func (n PluginSpecs) toIntermediate() []PluginSpec {
	intermediate := make([]PluginSpec, 0, n.Size())
	n.ForEach(func(spec PluginSpec) {
		intermediate = append(intermediate, spec)
	})
	return intermediate
}

func (n PluginSpecs) fromIntermediate(specs []PluginSpec) PluginSpecs {
	return MakePluginSpecs(specs...)
}

// CodecEncodeSelf implements codec.Selfer
func (n *PluginSpecs) CodecEncodeSelf(encoder *codec.Encoder) {
	if n.psMap != nil {
		encoder.Encode(n.toIntermediate())
	} else {
		encoder.Encode(nil)
	}
}

// CodecDecodeSelf implements codec.Selfer
func (n *PluginSpecs) CodecDecodeSelf(decoder *codec.Decoder) {
	in := []PluginSpec{}
	if err := decoder.Decode(&in); err != nil {
		return
	}
	*n = PluginSpecs{}.fromIntermediate(in)
}

// MarshalJSON shouldn't be used, use CodecEncodeSelf instead
func (PluginSpecs) MarshalJSON() ([]byte, error) {
	panic("MarshalJSON shouldn't be used, use CodecEncodeSelf instead")
}

// UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead
func (*PluginSpecs) UnmarshalJSON(b []byte) error {
	panic("UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead")
}

// GobEncode implements gob.Marshaller
func (n PluginSpecs) GobEncode() ([]byte, error) {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(n.toIntermediate())
	return buf.Bytes(), err
}

// GobDecode implements gob.Unmarshaller
func (n *PluginSpecs) GobDecode(input []byte) error {
	in := []PluginSpec{}
	if err := gob.NewDecoder(bytes.NewBuffer(input)).Decode(&in); err != nil {
		return err
	}
	*n = PluginSpecs{}.fromIntermediate(in)
	return nil
}

// PluginSpecsByID implements sort.Interface, so we can sort the specs by the
// ID field.
type PluginSpecsByID []PluginSpec

// Len is part of sort.Interface.
func (p PluginSpecsByID) Len() int {
	return len(p)
}

// Swap is part of sort.Interface.
func (p PluginSpecsByID) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

// Less is part of sort.Interface.
func (p PluginSpecsByID) Less(i, j int) bool {
	return p[i].ID < p[j].ID
}
