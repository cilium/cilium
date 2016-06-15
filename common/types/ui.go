package types

import (
	"bufio"
	"bytes"
	"fmt"
	"image/color"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/noironetworks/cilium-net/bpf/policymap"
)

const (
	addOp       = "add"
	modOp       = "mod"
	delOp       = "del"
	nodeObjType = "node"
	edgeObjType = "edge"
)

type UITopo struct {
	uiTopoMU sync.Mutex
	uiNodes  map[int]*UINode
	uiEdges  map[string]*UIEdge
	UIChan   chan UIUpdateMsg
}

func NewUITopo() UITopo {
	return UITopo{
		uiNodes: map[int]*UINode{},
		uiEdges: map[string]*UIEdge{},
		UIChan:  make(chan UIUpdateMsg, 10),
	}
}

type UINode struct {
	ID       int     `json:"id"`
	Size     int     `json:"size"`
	Label    string  `json:"label"`
	Labels   []Label `json:"-"`
	Image    string  `json:"image"`
	Title    string  `json:"title"`
	refCount int     `json:"-"`
}

func newuiNode(id, refCount int, lbls []Label) *UINode {
	return &UINode{
		ID:       id,
		refCount: refCount,
		Labels:   lbls,
		Image:    getImagePath(refCount),
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
	n.Image = getImagePath(n.refCount)
	n.Title = fmt.Sprintf("SecLabel ID %d", n.ID)
}

func (t *UITopo) AddOrUpdateNode(id32 uint32, lbls []Label, refCount int) {
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
	svgByte := createSVG(refCount)
	if err := writeSVGFile(refCount, "./", svgByte); err != nil {
		log.Errorf("%s", err)
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
	}
}

func (t *UITopo) GetNodes() []UINode {
	t.uiTopoMU.Lock()
	defer t.uiTopoMU.Unlock()
	nodes := []UINode{}
	for _, node := range t.uiNodes {
		node.Build()
		nodes = append(nodes, *node)
	}
	return nodes
}

type UIEdge struct {
	ID         string    `json:"id"`
	From       int       `json:"from"`
	To         int       `json:"to"`
	Value      int64     `json:"value"`
	Removed    bool      `json:"dashes"`
	Color      string    `json:"color"`
	Title      string    `json:"title"`
	Length     int       `json:"length,omitempty"`
	lastChange time.Time `json:"-"`
	color      uiColor   `json:"-"`
	bytes      uint64    `json:"-"`
	packets    uint64    `json:"-"`
}

func newuiEdge(from, to int) *UIEdge {
	return &UIEdge{
		ID:    getUIEdgeID(from, to),
		From:  from,
		To:    to,
		color: green,
	}
}

func getUIEdgeID(from, to int) string {
	return fmt.Sprintf("%d-%d", from, to)
}

func (e *UIEdge) Build() {
	if !e.Removed {
		e.color = green
		mbps := float64(float64(e.bytes*8) / float64(1000000))
		e.Value = int64(2.0 + mbps)
		e.Title = fmt.Sprintf("%.2f Mbps", mbps)
	} else {
		e.Value = 1
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
		if edge.Removed {
			edge.Removed = false
			updateUI = true
		}
		if pe != nil {
			if edge.bytes != pe.Bytes {
				edge.bytes = pe.Bytes
				updateUI = true
			}
			if edge.packets != pe.Packets {
				edge.packets = pe.Packets
				updateUI = true
			}
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
	t.uiTopoMU.Lock()
	defer t.uiTopoMU.Unlock()
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
	t.uiTopoMU.Lock()
	for _, edge := range t.uiEdges {
		if edge.Removed {
			if edge.lastChange.Add(10 * time.Second).Before(time.Now()) {
				delMsgs = append(delMsgs, NewUIUpdateMsg().Del().Edge(*edge).Build())
			} else {
				edge.color.Grayer()
				modMsgs = append(modMsgs, NewUIUpdateMsg().Mod().Edge(*edge).Build())
			}
		}
	}
	for _, msg := range delMsgs {
		t.UIChan <- msg
		delete(t.uiEdges, msg.RemoveID)
	}
	for _, msg := range modMsgs {
		t.UIChan <- msg
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

func writeSVGFile(refCount int, dir string, svg []byte) error {
	fileName := getImagePath(refCount)
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		return nil
	}
	f, err := os.Create(fileName)
	if err != nil {
		d, _ := os.Getwd()
		return fmt.Errorf("%s failed to open file %s for writing: %s", d, fileName, err)

	}
	defer f.Close()

	fw := bufio.NewWriter(f)

	_, err = fw.Write(svg)
	if err != nil {
		return err
	}
	return fw.Flush()
}

type UIUpdateMsg struct {
	RemoveID string  `json:"id,omitempty"`
	UINode   *UINode `json:"node,omitempty"`
	UIEdge   *UIEdge `json:"edge,omitempty"`
	Type     string  `json:"type"`
	op       string  `json:"-"`
	objType  string  `json:"-"`
}

func NewUIUpdateMsg() UIUpdateMsg {
	return UIUpdateMsg{}
}

func (u UIUpdateMsg) Add() UIUpdateMsg {
	u.op = addOp
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

func getImagePath(id int) string {
	return fmt.Sprintf("./static/%d.svg", id)
}

var (
	svgModel = `<svg height="{{.Height}}" width="{{.Width}}" xmlns="http://www.w3.org/2000/svg">
<text y="{{.Y}}" text-anchor="middle" x="{{.X}}" font-size="{{.FontSize}}" alignment-baseline="central">{{.ID}}</text>
</svg>
`

	svgTempl = template.Must(template.New("").Parse(svgModel))
)

func createSVG(nEP int) []byte {
	type svgProp struct {
		ID       int
		Height   int
		Width    int
		Y        int
		X        int
		FontSize int
	}
	createSVGConf := func(h, fontSize int) svgProp {
		return svgProp{
			Height:   h,
			Width:    h,
			Y:        h / 2,
			X:        h / 2,
			FontSize: fontSize,
		}
	}

	var svgConf svgProp

	switch len(strconv.Itoa(nEP)) {
	case 1:
		svgConf = createSVGConf(10, 10)
	case 2:
		svgConf = createSVGConf(20, 12)
	case 3:
		svgConf = createSVGConf(20, 10)
	case 4:
		svgConf = createSVGConf(20, 7)
	case 5:
		svgConf = createSVGConf(20, 6)
	case 6:
		svgConf = createSVGConf(20, 5)
	case 7:
		svgConf = createSVGConf(30, 6)
	case 8:
		svgConf = createSVGConf(40, 7)
	case 9:
		svgConf = createSVGConf(40, 6)
	default:
		svgConf = createSVGConf(40, 5)
	}

	svgConf.ID = nEP
	buf := new(bytes.Buffer)
	svgTempl.Execute(buf, svgConf)

	return buf.Bytes()
}
