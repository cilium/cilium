package report

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"reflect"
	"sort"

	"github.com/ugorji/go/codec"
	"github.com/weaveworks/ps"
)

// Counters is a string->int map.
type Counters struct {
	psMap ps.Map
}

// EmptyCounters is the set of empty counters.
var EmptyCounters = Counters{ps.NewMap()}

// MakeCounters returns EmptyCounters
func MakeCounters() Counters {
	return EmptyCounters
}

// Copy is a noop
func (c Counters) Copy() Counters {
	return c
}

// Add value to the counter 'key'
func (c Counters) Add(key string, value int) Counters {
	if c.psMap == nil {
		c = EmptyCounters
	}
	if existingValue, ok := c.psMap.Lookup(key); ok {
		value += existingValue.(int)
	}
	return Counters{
		c.psMap.Set(key, value),
	}
}

// Lookup the counter 'key'
func (c Counters) Lookup(key string) (int, bool) {
	if c.psMap != nil {
		existingValue, ok := c.psMap.Lookup(key)
		if ok {
			return existingValue.(int), true
		}
	}
	return 0, false
}

// Size returns the number of counters
func (c Counters) Size() int {
	if c.psMap == nil {
		return 0
	}
	return c.psMap.Size()
}

// Merge produces a fresh Counters, container the keys from both inputs. When
// both inputs container the same key, the latter value is used.
func (c Counters) Merge(other Counters) Counters {
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
			output = output.Set(key, otherVal.(int)+val.(int))
		} else {
			output = output.Set(key, otherVal)
		}
	})
	return Counters{output}
}

// ForEach calls f for each k/v pair of counters. Keys are iterated in
// lexicographical order.
func (c Counters) ForEach(f func(key string, val int)) {
	if c.psMap != nil {
		keys := c.psMap.Keys()
		sort.Strings(keys)
		for _, key := range keys {
			if val, ok := c.psMap.Lookup(key); ok {
				f(key, val.(int))
			}
		}
	}
}

// String serializes Counters into a string.
func (c Counters) String() string {
	buf := bytes.NewBufferString("{")
	prefix := ""
	c.ForEach(func(k string, v int) {
		fmt.Fprintf(buf, "%s%s: %d", prefix, k, v)
		prefix = ", "
	})
	fmt.Fprintf(buf, "}")
	return buf.String()
}

// DeepEqual tests equality with other Counters
func (c Counters) DeepEqual(d Counters) bool {
	if (c.psMap == nil) != (d.psMap == nil) {
		return false
	} else if c.psMap == nil && d.psMap == nil {
		return true
	}

	if c.psMap.Size() != d.psMap.Size() {
		return false
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

func (c Counters) toIntermediate() map[string]int {
	intermediate := map[string]int{}
	c.ForEach(func(key string, val int) {
		intermediate[key] = val
	})
	return intermediate
}

func (c Counters) fromIntermediate(in map[string]int) Counters {
	out := ps.NewMap()
	for k, v := range in {
		out = out.Set(k, v)
	}
	return Counters{out}
}

// CodecEncodeSelf implements codec.Selfer
func (c *Counters) CodecEncodeSelf(encoder *codec.Encoder) {
	encoder.Encode(c.toIntermediate())
}

// CodecDecodeSelf implements codec.Selfer
func (c *Counters) CodecDecodeSelf(decoder *codec.Decoder) {
	in := map[string]int{}
	if err := decoder.Decode(&in); err != nil {
		return
	}
	*c = Counters{}.fromIntermediate(in)
}

// MarshalJSON shouldn't be used, use CodecEncodeSelf instead
func (Counters) MarshalJSON() ([]byte, error) {
	panic("MarshalJSON shouldn't be used, use CodecEncodeSelf instead")
}

// UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead
func (*Counters) UnmarshalJSON(b []byte) error {
	panic("UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead")
}

// GobEncode implements gob.Marshaller
func (c Counters) GobEncode() ([]byte, error) {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(c.toIntermediate())
	return buf.Bytes(), err
}

// GobDecode implements gob.Unmarshaller
func (c *Counters) GobDecode(input []byte) error {
	in := map[string]int{}
	if err := gob.NewDecoder(bytes.NewBuffer(input)).Decode(&in); err != nil {
		return err
	}
	*c = Counters{}.fromIntermediate(in)
	return nil
}
