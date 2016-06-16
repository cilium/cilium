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

type EndpointOption struct {
	Define      string
	Description string
	Immutable   bool
}

const (
	OptionNAT46            = "NAT46"
	OptionDisablePolicy    = "DisablePolicy"
	OptionDropNotify       = "DropNotification"
	OptionDisableConntrack = "DisableConntrack"
	OptionDebug            = "Debug"
	OptionAllowToHost      = "AllowToHost"
	OptionAllowToWorld     = "AllowToWorld"
)

var (
	OptionSpecNAT46 = EndpointOption{
		Define:      "ENABLE_NAT46",
		Description: "Enable automatic NAT46 translation",
	}

	OptionSpecDisablePolicy = EndpointOption{
		Define:      "DISABLE_POLICY_ENFORCEMENT",
		Description: "Disable policy enforcement",
	}

	OptionSpecDropNotify = EndpointOption{
		Define:      "DROP_NOTIFY",
		Description: "Enable drop notifications",
	}

	OptionSpecDisableConntrack = EndpointOption{
		Define:      "DISABLE_CONNTRACK",
		Description: "Disable stateful connection tracking",
	}

	OptionSpecDebug = EndpointOption{
		Define:      "DEBUG",
		Description: "Enable debugging trace statements",
	}

	OptionSpecAllowToHost = EndpointOption{
		Define:      "ALLOW_TO_HOST",
		Immutable:   true,
		Description: "Allow all traffic to local host",
	}

	OptionSpecAllowToWorld = EndpointOption{
		Define:      "ALLOW_TO_WORLD",
		Immutable:   true,
		Description: "Allow all traffic to outside world",
	}

	EndpointOptionLibrary = map[string]*EndpointOption{
		OptionNAT46:            &OptionSpecNAT46,
		OptionDisablePolicy:    &OptionSpecDisablePolicy,
		OptionDropNotify:       &OptionSpecDropNotify,
		OptionDisableConntrack: &OptionSpecDisableConntrack,
		OptionDebug:            &OptionSpecDebug,
		OptionAllowToHost:      &OptionSpecAllowToHost,
		OptionAllowToWorld:     &OptionSpecAllowToWorld,
	}
)

func LookupEndpointOption(name string) (string, *EndpointOption) {
	nameLower := strings.ToLower(name)

	for k, _ := range EndpointOptionLibrary {
		if strings.ToLower(k) == nameLower {
			return k, EndpointOptionLibrary[k]
		}
	}

	return "", nil
}

func EndpointOptionDefine(name string) string {
	if _, ok := EndpointOptionLibrary[name]; ok {
		return EndpointOptionLibrary[name].Define
	}

	return ""
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

func (e *Endpoint) OptionSet(key string) bool {
	set, exists := e.Opts[key]
	return exists && set
}

// GetFmtOpt returns #define name if option exists and is set to true in endpoint's Opts
// map or #undef name if option does not exist or exists but is set to false in endpoint's
// Opts map.
func (e *Endpoint) GetFmtOpt(name string) string {
	if e.OptionSet(name) {
		return "#define " + EndpointOptionDefine(name)
	}

	return "#undef " + name
}

func (e *Endpoint) OptionChanged(key string, value bool) {
	switch key {
	case OptionDisableConntrack:
		e.InvalidatePolicy()
	}
}

func (e *Endpoint) ApplyOpts(opts EPOpts) bool {
	changes := 0

	for k, v := range opts {
		val, ok := e.Opts[k]

		if v {
			/* Only enable if not enabled already */
			if !ok || !val {
				e.Opts[k] = true
				changes++
				e.OptionChanged(k, v)
			}
		} else {
			/* Only disable if enabled already */
			if ok && val {
				delete(e.Opts, k)
				changes++
				e.OptionChanged(k, v)
			}
		}
	}

	return changes > 0
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

// IsLibnetwork returns true if the endpoint was created by Libnetwork, false otherwise.
func (e *Endpoint) IsLibnetwork() bool {
	return e.DockerNetworkID != ""
}

// IsCNI returns true if the endpoint was created by CNI, false otherwise.
func (e *Endpoint) IsCNI() bool {
	return e.DockerNetworkID == ""
}

func (e *Endpoint) PolicyMapPath() string {
	return common.PolicyMapPath + e.ID
}

func (e *Endpoint) InvalidatePolicy() {
	if e.Consumable != nil {
		// Resetting to 0 will trigger a regeneration on the next update
		log.Debugf("Invalidated policy for endpoint %s", e.ID)
		e.Consumable.Iteration = 0
	}
}
