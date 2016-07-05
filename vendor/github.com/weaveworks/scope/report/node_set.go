package report

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

// NodeSet is a set of nodes keyed on ID. Clients must use
// the Add method to add nodes
type NodeSet struct {
	psMap ps.Map
}

// EmptyNodeSet is the empty set of nodes.
var EmptyNodeSet = NodeSet{ps.NewMap()}

// MakeNodeSet makes a new NodeSet with the given nodes.
func MakeNodeSet(nodes ...Node) NodeSet {
	return EmptyNodeSet.Add(nodes...)
}

// Add adds the nodes to the NodeSet. Add is the only valid way to grow a
// NodeSet. Add returns the NodeSet to enable chaining.
func (n NodeSet) Add(nodes ...Node) NodeSet {
	result := n.psMap
	if result == nil {
		result = ps.NewMap()
	}
	for _, node := range nodes {
		result = result.Set(node.ID, node)
	}
	return NodeSet{result}
}

// Delete deletes the nodes from the NodeSet by ID. Delete is the only valid
// way to shrink a NodeSet. Delete returns the NodeSet to enable chaining.
func (n NodeSet) Delete(ids ...string) NodeSet {
	if n.Size() == 0 {
		return n
	}
	result := n.psMap
	for _, id := range ids {
		result = result.Delete(id)
	}
	if result.Size() == 0 {
		return EmptyNodeSet
	}
	return NodeSet{result}
}

// Merge combines the two NodeSets and returns a new result.
func (n NodeSet) Merge(other NodeSet) NodeSet {
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
	return NodeSet{result}
}

// Lookup the node 'key'
func (n NodeSet) Lookup(key string) (Node, bool) {
	if n.psMap != nil {
		value, ok := n.psMap.Lookup(key)
		if ok {
			return value.(Node), true
		}
	}
	return Node{}, false
}

// Keys is a list of all the keys in this set.
func (n NodeSet) Keys() []string {
	if n.psMap == nil {
		return nil
	}
	k := n.psMap.Keys()
	sort.Strings(k)
	return k
}

// Size is the number of nodes in the set
func (n NodeSet) Size() int {
	if n.psMap == nil {
		return 0
	}
	return n.psMap.Size()
}

// ForEach executes f for each node in the set. Nodes are traversed in sorted
// order.
func (n NodeSet) ForEach(f func(Node)) {
	for _, key := range n.Keys() {
		if val, ok := n.psMap.Lookup(key); ok {
			f(val.(Node))
		}
	}
}

// Copy is a noop
func (n NodeSet) Copy() NodeSet {
	return n
}

func (n NodeSet) String() string {
	keys := []string{}
	if n.psMap == nil {
		n = EmptyNodeSet
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

// DeepEqual tests equality with other NodeSets
func (n NodeSet) DeepEqual(i interface{}) bool {
	d, ok := i.(NodeSet)
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

func (n NodeSet) toIntermediate() []Node {
	intermediate := make([]Node, 0, n.Size())
	n.ForEach(func(node Node) {
		intermediate = append(intermediate, node)
	})
	return intermediate
}

func (n NodeSet) fromIntermediate(nodes []Node) NodeSet {
	return MakeNodeSet(nodes...)
}

// CodecEncodeSelf implements codec.Selfer
func (n *NodeSet) CodecEncodeSelf(encoder *codec.Encoder) {
	if n.psMap != nil {
		encoder.Encode(n.toIntermediate())
	} else {
		encoder.Encode(nil)
	}
}

// CodecDecodeSelf implements codec.Selfer
func (n *NodeSet) CodecDecodeSelf(decoder *codec.Decoder) {
	in := []Node{}
	if err := decoder.Decode(&in); err != nil {
		return
	}
	*n = NodeSet{}.fromIntermediate(in)
}

// MarshalJSON shouldn't be used, use CodecEncodeSelf instead
func (NodeSet) MarshalJSON() ([]byte, error) {
	panic("MarshalJSON shouldn't be used, use CodecEncodeSelf instead")
}

// UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead
func (*NodeSet) UnmarshalJSON(b []byte) error {
	panic("UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead")
}

// GobEncode implements gob.Marshaller
func (n NodeSet) GobEncode() ([]byte, error) {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(n.toIntermediate())
	return buf.Bytes(), err
}

// GobDecode implements gob.Unmarshaller
func (n *NodeSet) GobDecode(input []byte) error {
	in := []Node{}
	if err := gob.NewDecoder(bytes.NewBuffer(input)).Decode(&in); err != nil {
		return err
	}
	*n = NodeSet{}.fromIntermediate(in)
	return nil
}
