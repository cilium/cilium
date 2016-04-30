package types

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"

	"github.com/noironetworks/cilium-net/bpf/policymap"
	"github.com/noironetworks/cilium-net/common"
)

// EPPortMap is the port mapping representation for a particular endpoint.
type EPPortMap struct {
	From  uint16 `json:"from"`
	To    uint16 `json:"to"`
	Proto uint8  `json:"proto"`
}

// Opts is the endpoint bpf options representation.
type EPOpts map[string]bool

// Endpoint contains all the details for a particular LXC and the host interface to where
// is connected to.
type Endpoint struct {
	ID            string `json:"id"`              // Endpoint ID.
	DockerID      string `json:"docker-id"`       // Docker ID.
	DockerNetwork string `json:"docker-network"`  // Docker network ID.
	IfName        string `json:"interface-name"`  // Container's interface name.
	LXCMAC        MAC    `json:"lxc-mac"`         // Container MAC address.
	LXCIP         net.IP `json:"lxc-ip"`          // Container IPv6 address.
	IfIndex       int    `json:"interface-index"` // Host's interface index.
	NodeMAC       MAC    `json:"node-mac"`        // Node MAC address.
	NodeIP        net.IP `json:"node-ip"`         // Node IPv6 address.
	// TODO: change uint32 to uint16 since we only support 0xffff labels
	SecLabelID uint32               `json:"security-label"` // Security Label ID set to this endpoint.
	PortMap    []EPPortMap          `json:"port-mapping"`   // Port mapping used for this endpoint.
	Consumable *Consumable          `json:"consumable"`
	PolicyMap  *policymap.PolicyMap `json:"-"`
	Opts       EPOpts               `json:"options"` // Endpoint bpf options.
}

// U16ID returns the endpoint's ID as uint16.
func (e *Endpoint) U16ID() uint16 {
	n, _ := strconv.ParseUint(e.ID, 10, 16)
	return uint16(n)
}

// SetID sets the endpoint's host local unique ID.
func (e *Endpoint) SetID() {
	e.ID = strconv.FormatUint(uint64(common.EndpointAddr2ID(e.LXCIP)), 10)
}

func (e *Endpoint) SetSecLabel(labels *SecCtxLabel) {
	e.SecLabelID = uint32(labels.ID)
	e.Consumable = GetConsumable(labels.ID, labels)
}

func (e *Endpoint) Allows(id int) bool {
	if e.Consumable != nil {
		return e.Consumable.Allows(id)
	} else {
		return false
	}
}

// IPv4Address returns the TODO: what does this do?
func (e *Endpoint) IPv4Address(v4Range *net.IPNet) *net.IP {
	ip := common.DupIP(v4Range.IP)

	id := e.U16ID()
	ip[2] = byte(id >> 8)
	ip[3] = byte(id & 0xff)

	return &ip
}

// String returns endpoint on a JSON format.
func (e Endpoint) String() string {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// GetFmtOpt returns #define name if option exists and is set to true in endpoint's Opts
// map or #undef name if option does not exist or exists but is set to false in endpoint's
// Opts map.
func (e *Endpoint) GetFmtOpt(name string) string {
	set, exists := e.Opts[name]
	if !exists {
		return "#undef " + name
	}
	if set {
		return "#define " + name
	}
	return "#undef " + name
}

type orderEndpoint func(e1, e2 *Endpoint) bool

// OrderEndpointAsc orders the slice of Endpoint in ascending ID order.
func OrderEndpointAsc(eps []Endpoint) {
	ascPriority := func(e1, e2 *Endpoint) bool {
		e1Int, _ := strconv.ParseUint(e1.ID, 10, 64)
		e2Int, _ := strconv.ParseUint(e2.ID, 10, 64)
		return e1Int < e2Int
	}
	orderEndpoint(ascPriority).sort(eps)
}

func (by orderEndpoint) sort(eps []Endpoint) {
	dS := &epSorter{
		eps: eps,
		by:  by,
	}
	sort.Sort(dS)
}

type epSorter struct {
	eps []Endpoint
	by  func(e1, e2 *Endpoint) bool
}

func (epS *epSorter) Len() int {
	return len(epS.eps)
}

func (epS *epSorter) Swap(i, j int) {
	epS.eps[i], epS.eps[j] = epS.eps[j], epS.eps[i]
}

func (epS *epSorter) Less(i, j int) bool {
	return epS.by(&epS.eps[i], &epS.eps[j])
}
