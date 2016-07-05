package report

import (
	"time"

	"github.com/ugorji/go/codec"
	"github.com/weaveworks/scope/common/mtime"
)

// Controls describe the control tags within the Nodes
type Controls map[string]Control

// A Control basically describes an RPC
type Control struct {
	ID    string `json:"id"`
	Human string `json:"human"`
	Icon  string `json:"icon"` // from https://fortawesome.github.io/Font-Awesome/cheatsheet/ please
	Rank  int    `json:"rank"`
}

// Merge merges other with cs, returning a fresh Controls.
func (cs Controls) Merge(other Controls) Controls {
	result := cs.Copy()
	for k, v := range other {
		result[k] = v
	}
	return result
}

// Copy produces a copy of cs.
func (cs Controls) Copy() Controls {
	result := Controls{}
	for k, v := range cs {
		result[k] = v
	}
	return result
}

// AddControl adds c added to cs.
func (cs Controls) AddControl(c Control) {
	cs[c.ID] = c
}

// AddControls adds a collection of controls to cs.
func (cs Controls) AddControls(controls []Control) {
	for _, c := range controls {
		cs[c.ID] = c
	}
}

// NodeControls represent the individual controls that are valid for a given
// node at a given point in time.  It's immutable. A zero-value for Timestamp
// indicated this NodeControls is 'not set'.
type NodeControls struct {
	Timestamp time.Time
	Controls  StringSet
}

// MakeNodeControls makes a new NodeControls
func MakeNodeControls() NodeControls {
	return NodeControls{
		Controls: MakeStringSet(),
	}
}

// Copy is a noop, as NodeControls is immutable
func (nc NodeControls) Copy() NodeControls {
	return nc
}

// Merge returns the newest of the two NodeControls; it does not take the union
// of the valid Controls.
func (nc NodeControls) Merge(other NodeControls) NodeControls {
	if nc.Timestamp.Before(other.Timestamp) {
		return other
	}
	return nc
}

// Add the new control IDs to this NodeControls, producing a fresh NodeControls.
func (nc NodeControls) Add(ids ...string) NodeControls {
	return NodeControls{
		Timestamp: mtime.Now(),
		Controls:  nc.Controls.Add(ids...),
	}
}

// WireNodeControls is the intermediate type for encoding/decoding.
// Only needed for backwards compatibility with probes
// (time.Time is encoded in binary in MsgPack)
type wireNodeControls struct {
	Timestamp string    `json:"timestamp,omitempty"`
	Controls  StringSet `json:"controls,omitempty"`
}

// CodecEncodeSelf implements codec.Selfer
func (nc *NodeControls) CodecEncodeSelf(encoder *codec.Encoder) {
	encoder.Encode(wireNodeControls{
		Timestamp: renderTime(nc.Timestamp),
		Controls:  nc.Controls,
	})
}

// CodecDecodeSelf implements codec.Selfer
func (nc *NodeControls) CodecDecodeSelf(decoder *codec.Decoder) {
	in := wireNodeControls{}
	if err := decoder.Decode(&in); err != nil {
		return
	}
	*nc = NodeControls{
		Timestamp: parseTime(in.Timestamp),
		Controls:  in.Controls,
	}
}

// MarshalJSON shouldn't be used, use CodecEncodeSelf instead
func (NodeControls) MarshalJSON() ([]byte, error) {
	panic("MarshalJSON shouldn't be used, use CodecEncodeSelf instead")
}

// UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead
func (*NodeControls) UnmarshalJSON(b []byte) error {
	panic("UnmarshalJSON shouldn't be used, use CodecDecodeSelf instead")
}

// NodeControlData contains specific information about the control. It
// is used as a Value field of LatestEntry in NodeControlDataLatestMap.
type NodeControlData struct {
	Dead bool `json:"dead"`
}
