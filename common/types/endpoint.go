package types

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

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
	ID               string               `json:"id"`                 // Endpoint ID.
	DockerID         string               `json:"docker-id"`          // Docker ID.
	DockerNetworkID  string               `json:"docker-network-id"`  // Docker network ID.
	DockerEndpointID string               `json:"docker-endpoint-id"` // Docker endpoint ID.
	IfName           string               `json:"interface-name"`     // Container's interface name.
	LXCMAC           MAC                  `json:"lxc-mac"`            // Container MAC address.
	LXCIP            net.IP               `json:"lxc-ip"`             // Container IPv6 address.
	IfIndex          int                  `json:"interface-index"`    // Host's interface index.
	NodeMAC          MAC                  `json:"node-mac"`           // Node MAC address.
	NodeIP           net.IP               `json:"node-ip"`            // Node IPv6 address.
	SecLabel         *SecCtxLabel         `json:"security-label"`     // Security Label  set to this endpoint.
	PortMap          []EPPortMap          `json:"port-mapping"`       // Port mapping used for this endpoint.
	Consumable       *Consumable          `json:"consumable"`
	PolicyMap        *policymap.PolicyMap `json:"-"`
	Opts             EPOpts               `json:"options"` // Endpoint bpf options.
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
	e.SecLabel = labels
	e.Consumable = GetConsumable(labels.ID, labels)
}

func (e *Endpoint) Allows(id uint32) bool {
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

// Base64 returns the endpoint in a base64 format.
func (ep Endpoint) Base64() (string, error) {
	jsonBytes, err := json.Marshal(ep)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

// ParseBase64ToEndpoint parses the endpoint stored in the given base64 string.
func ParseBase64ToEndpoint(str string, ep *Endpoint) error {
	jsonBytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	return json.Unmarshal(jsonBytes, ep)
}

// FilterEPDir returns a list of directories' names that possible belong to an endpoint.
func FilterEPDir(dirFiles []os.FileInfo) []string {
	eptsID := []string{}
	for _, file := range dirFiles {
		if file.IsDir() {
			if _, err := strconv.ParseUint(file.Name(), 10, 16); err == nil {
				eptsID = append(eptsID, file.Name())
			}
		}
	}
	return eptsID
}

// ParseEndpoint parses the given strEp which is in the form of:
// common.CiliumCHeaderPrefix + common.Version + ":" + endpointBase64
func ParseEndpoint(strEp string) (*Endpoint, error) {
	// TODO: Provide a better mechanism to update from old version once we bump
	// TODO: cilium version.
	strEpSlice := strings.Split(strEp, ":")
	if len(strEpSlice) != 2 {
		return nil, fmt.Errorf("invalid format %q. Should contain a single ':'", strEp)
	}
	var ep Endpoint
	if err := ParseBase64ToEndpoint(strEpSlice[1], &ep); err != nil {
		return nil, fmt.Errorf("failed to parse base64toendpoint: %s", err)
	}
	return &ep, nil
}
