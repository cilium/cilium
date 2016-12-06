//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package types

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/bpf/policymap"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	addOp       = "add"
	aniOp       = "animate"
	modOp       = "mod"
	delOp       = "del"
	nodeObjType = "node"
	edgeObjType = "edge"
)

type UITopo struct {
	uiTopoMU *sync.RWMutex
	uiNodes  map[int]*UINode
	uiEdges  map[string]*UIEdge
	UIChan   chan UIUpdateMsg
}

func NewUITopo() UITopo {
	return UITopo{
		uiTopoMU: &sync.RWMutex{},
		uiNodes:  map[int]*UINode{},
		uiEdges:  map[string]*UIEdge{},
		UIChan:   make(chan UIUpdateMsg, 10),
	}
}

type UINode struct {
	ID       int            `json:"id"`
	Size     int            `json:"size"`
	Label    string         `json:"label"`
	Labels   []labels.Label `json:"-"`
	Title    string         `json:"title"`
	refCount int
}

func newuiNode(id, refCount int, lbls []labels.Label) *UINode {
	return &UINode{
		ID:       id,
		refCount: refCount,
		Labels:   lbls,
	}
}

func (n *UINode) Build() {
	n.Label = ""
	if n.Labels != nil {
		lblsStr := []string{}
		for _, l := range n.Labels {
			lblsStr = append(lblsStr, l.String())
		}
		n.Label = strings.Join(lblsStr, "\n")
	}
	n.Size = 10 + n.refCount
	n.Title = fmt.Sprintf("SecLabel ID %d", n.ID)
}

func (t *UITopo) AddOrUpdateNode(id32 uint32, lbls []labels.Label, refCount int) {
	id := int(id32)

	t.uiTopoMU.Lock()
	defer t.uiTopoMU.Unlock()

	node, exists := t.uiNodes[id]

	var msg UIUpdateMsg

	if exists {
		node.refCount = refCount
		node.Labels = lbls
		msg = NewUIUpdateMsg().Mod().Node(*node).Build()
	} else {
		node := newuiNode(id, refCount, lbls)
		t.uiNodes[id] = node
		msg = NewUIUpdateMsg().Add().Node(*node).Build()
	}
	t.UIChan <- msg
}

func (t *UITopo) DeleteNode(id32 uint32) {
	id := int(id32)

	t.uiTopoMU.Lock()
	defer t.uiTopoMU.Unlock()

	node, exists := t.uiNodes[id]

	var msg UIUpdateMsg

	if exists {
		node.Build()
		msg = NewUIUpdateMsg().Del().Node(*node).Build()
		t.UIChan <- msg
		delete(t.uiNodes, id)
	}
}

func (t *UITopo) GetNodes() []UINode {
	t.uiTopoMU.RLock()
	defer t.uiTopoMU.RUnlock()
	nodes := []UINode{}
	for _, node := range t.uiNodes {
		node.Build()
		nodes = append(nodes, *node)
	}
	return nodes
}

type UIAnimateEdge struct {
	Edge        string `json:"edge"`
	TrafficSize uint64 `json:"trafficSize"`
}

type UIEdge struct {
	ID            string `json:"id"`
	From          int    `json:"from"`
	To            int    `json:"to"`
	Value         int64  `json:"value"`
	Removed       bool   `json:"dashes"`
	Color         string `json:"color"`
	Title         string `json:"title"`
	Length        int    `json:"length,omitempty"`
	color         uiColor
	lastChange    time.Time
	lastUpdate    time.Time
	update        time.Time
	lastBytes     uint64
	lastPackets   uint64
	bytes         uint64
	packets       uint64
	UIAnimateEdge `json:"-"`
}

func newuiEdge(from, to int) *UIEdge {
	return &UIEdge{
		ID:            getUIEdgeID(from, to),
		UIAnimateEdge: UIAnimateEdge{Edge: getUIEdgeID(from, to)},
		From:          from,
		To:            to,
		color:         green,
	}
}

func getUIEdgeID(from, to int) string {
	return fmt.Sprintf("%d-%d", from, to)
}

func (e *UIEdge) Build() {
	if !e.Removed {
		e.color = green

		if nPackets := e.packets - e.lastPackets; nPackets > 50 {
			e.TrafficSize = 50
		} else {
			e.TrafficSize = nPackets
		}

		nBytes := e.bytes - e.lastBytes
		duration := e.update.Sub(e.lastUpdate)
		bytesPerSec := float64(nBytes) / duration.Seconds()

		if bytesPerSec >= 1024 {
			mbytesPerSec := bytesPerSec / 1024
			if mbytesPerSec >= 1024 {
				gBytePerSec := mbytesPerSec / 1024
				if gBytePerSec >= 1024 {
					tBytePerSec := gBytePerSec / 1024
					e.Title = fmt.Sprintf("%.2f TBps", tBytePerSec)
				} else {
					e.Title = fmt.Sprintf("%.2f GBps", gBytePerSec)
				}
			} else {
				e.Title = fmt.Sprintf("%.2f MBps", mbytesPerSec)
			}
		} else {
			e.Title = fmt.Sprintf("%.2f Bps", bytesPerSec)
		}
		e.Value = int64(2.0 + bytesPerSec)

	} else {
		e.Value = 1
		e.TrafficSize = 0
		e.Title = fmt.Sprintf("Disconnected...")
	}
	if e.From == e.To {
		e.Length = 500
	}
	e.Color = e.color.String()
}

func (t *UITopo) AddOrUpdateEdge(from, to int, pe *policymap.PolicyEntry) {

	id := getUIEdgeID(from, to)

	t.uiTopoMU.Lock()
	defer t.uiTopoMU.Unlock()

	edge, exists := t.uiEdges[id]

	var msg UIUpdateMsg

	updateUI := false

	if exists {
		edge.lastChange = time.Now()
		edge.lastUpdate = edge.update
		edge.update = time.Now()
		if edge.Removed {
			edge.Removed = false
			updateUI = true
		}
		if pe != nil {
			updateUI = true
			edge.lastBytes = edge.bytes
			edge.bytes = pe.Bytes
			edge.lastPackets = edge.packets
			edge.packets = pe.Packets
		}
		msg = NewUIUpdateMsg().Mod().Edge(*edge).Build()
	} else {
		edge := newuiEdge(from, to)
		t.uiEdges[id] = edge
		msg = NewUIUpdateMsg().Add().Edge(*edge).Build()
		updateUI = true
	}
	if updateUI {
		t.UIChan <- msg
	}
}

func (t *UITopo) DeleteEdge(from, to int) {
	id := getUIEdgeID(from, to)

	t.uiTopoMU.Lock()
	defer t.uiTopoMU.Unlock()

	edge, exists := t.uiEdges[id]

	if exists && !edge.Removed {
		edge.lastChange = time.Now()
		edge.color = red
		edge.Removed = true
		msg := NewUIUpdateMsg().Mod().Edge(*edge).Build()
		t.UIChan <- msg
	}
}

func (t *UITopo) GetEdges() []UIEdge {
	t.uiTopoMU.RLock()
	defer t.uiTopoMU.RUnlock()
	edges := []UIEdge{}
	for _, edge := range t.uiEdges {
		edge.Build()
		edges = append(edges, *edge)
	}
	return edges
}

func (t *UITopo) RefreshEdges() {
	delMsgs := []UIUpdateMsg{}
	modMsgs := []UIUpdateMsg{}
	aniMsgEdges := NewUIUpdateMsg().Ani()
	t.uiTopoMU.Lock()
	for _, edge := range t.uiEdges {
		if edge.Removed {
			if edge.lastChange.Add(10 * time.Second).Before(time.Now()) {
				delMsgs = append(delMsgs, NewUIUpdateMsg().Del().Edge(*edge).Build())
			} else {
				edge.color.Grayer()
				modMsgs = append(modMsgs, NewUIUpdateMsg().Mod().Edge(*edge).Build())
			}
		} else {
			aniMsgEdges = aniMsgEdges.AnimatedEdge(*edge)
		}
	}
	for _, msg := range delMsgs {
		t.UIChan <- msg
		delete(t.uiEdges, msg.RemoveID)
	}
	for _, msg := range modMsgs {
		t.UIChan <- msg
	}

	nonZeroEdges := []UIAnimateEdge{}
	for _, edge := range aniMsgEdges.UIEdges {
		if edge.TrafficSize != 0 {
			nonZeroEdges = append(nonZeroEdges, edge)
		}
	}
	if len(nonZeroEdges) != 0 {
		aniMsgEdges.UIEdges = nonZeroEdges
		t.UIChan <- aniMsgEdges.Build()
	}

	t.uiTopoMU.Unlock()
}

type uiColor color.RGBA64

var (
	green = uiColor{51, 255, 51, 1}
	red   = uiColor{255, 51, 51, 1}
	grey  = uiColor{224, 224, 224, 1}
)

func (u uiColor) String() string {
	return fmt.Sprintf("rgba(%d,%d,%d,%d)", u.R, u.G, u.B, u.A)
}
func (u *uiColor) Grayer() {
	u.R = (u.R + grey.R) / 2
	u.G = (u.G + grey.G) / 2
	u.B = (u.B + grey.B) / 2
}

type UIUpdateMsg struct {
	RemoveID string          `json:"id,omitempty"`
	UINode   *UINode         `json:"node,omitempty"`
	UIEdge   *UIEdge         `json:"edge,omitempty"`
	UIEdges  []UIAnimateEdge `json:"edges,omitempty"`
	Type     string          `json:"type"`
	op       string
	objType  string
}

func NewUIUpdateMsg() UIUpdateMsg {
	return UIUpdateMsg{}
}

func (u UIUpdateMsg) Add() UIUpdateMsg {
	u.op = addOp
	return u
}

func (u UIUpdateMsg) Ani() UIUpdateMsg {
	u.op = aniOp
	return u
}

func (u UIUpdateMsg) Mod() UIUpdateMsg {
	u.op = modOp
	return u
}

func (u UIUpdateMsg) Del() UIUpdateMsg {
	u.op = delOp
	return u
}

func (u UIUpdateMsg) Node(node UINode) UIUpdateMsg {
	node.Build()
	u.UINode = &node
	u.objType = nodeObjType
	return u
}

func (u UIUpdateMsg) Edge(edge UIEdge) UIUpdateMsg {
	edge.Build()
	u.UIEdge = &edge
	u.objType = edgeObjType
	return u
}

func (u UIUpdateMsg) AnimatedEdge(edge UIEdge) UIUpdateMsg {
	edge.Build()
	if u.UIEdges == nil {
		u.UIEdges = []UIAnimateEdge{}
	}
	u.UIEdges = append(u.UIEdges, edge.UIAnimateEdge)
	u.objType = edgeObjType
	return u
}

func (u UIUpdateMsg) Build() UIUpdateMsg {
	if u.op == delOp {
		switch u.objType {
		case nodeObjType:
			u.RemoveID = strconv.Itoa(u.UINode.ID)
			u.UINode = nil
		case edgeObjType:
			u.RemoveID = u.UIEdge.ID
			u.UIEdge = nil
		}
	}

	u.Type = fmt.Sprintf("%s-%s", u.op, u.objType)
	return u
}
