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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/bpf/policymap"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
)

// EPPortMap is the port mapping representation for a particular endpoint.
type EPPortMap struct {
	From  uint16 `json:"from"`
	To    uint16 `json:"to"`
	Proto uint8  `json:"proto"`
}

const (
	OptionAllowToHost         = "AllowToHost"
	OptionAllowToWorld        = "AllowToWorld"
	OptionConntrackAccounting = "ConntrackAccounting"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDropNotify          = "DropNotification"
	OptionLearnTraffic        = "LearnTraffic"
	OptionNAT46               = "NAT46"
	OptionPolicy              = "Policy"

	maxLogs = 256
)

var (
	OptionSpecAllowToHost = Option{
		Define:      "ALLOW_TO_HOST",
		Immutable:   true,
		Description: "Allow all traffic to local host",
	}

	OptionSpecAllowToWorld = Option{
		Define:      "ALLOW_TO_WORLD",
		Immutable:   true,
		Description: "Allow all traffic to outside world",
	}

	OptionSpecConntrackAccounting = Option{
		Define:      "CONNTRACK_ACCOUNTING",
		Description: "Enable per flow (conntrack) statistics",
	}

	OptionSpecConntrack = Option{
		Define:      "CONNTRACK",
		Description: "Enable stateful connection tracking",
	}

	OptionSpecDebug = Option{
		Define:      "DEBUG",
		Description: "Enable debugging trace statements",
	}

	OptionSpecDropNotify = Option{
		Define:      "DROP_NOTIFY",
		Description: "Enable drop notifications",
	}

	OptionSpecLearnTraffic = Option{
		Define:      "LEARN_TRAFFIC",
		Description: "Learn and add labels to the list of allowed labels",
	}

	OptionSpecNAT46 = Option{
		Define:      "ENABLE_NAT46",
		Description: "Enable automatic NAT46 translation",
	}

	OptionSpecPolicy = Option{
		Define:      "POLICY_ENFORCEMENT",
		Description: "Enable policy enforcement",
	}

	EndpointMutableOptionLibrary = OptionLibrary{
		OptionConntrackAccounting: &OptionSpecConntrackAccounting,
		OptionConntrack:           &OptionSpecConntrack,
		OptionDebug:               &OptionSpecDebug,
		OptionDropNotify:          &OptionSpecDropNotify,
		OptionLearnTraffic:        &OptionSpecLearnTraffic,
		OptionNAT46:               &OptionSpecNAT46,
		OptionPolicy:              &OptionSpecPolicy,
	}

	EndpointOptionLibrary = OptionLibrary{
		OptionAllowToHost:  &OptionSpecAllowToHost,
		OptionAllowToWorld: &OptionSpecAllowToWorld,
	}
)

func init() {
	for k, v := range EndpointMutableOptionLibrary {
		EndpointOptionLibrary[k] = v
	}
}

// Endpoint contains all the details for a particular LXC and the host interface to where
// is connected to.
type Endpoint struct {
	ID               uint16                `json:"id"`                 // Endpoint ID.
	DockerID         string                `json:"docker-id"`          // Docker ID.
	DockerNetworkID  string                `json:"docker-network-id"`  // Docker network ID.
	DockerEndpointID string                `json:"docker-endpoint-id"` // Docker endpoint ID.
	IfName           string                `json:"interface-name"`     // Container's interface name.
	LXCMAC           MAC                   `json:"lxc-mac"`            // Container MAC address.
	IPv6             addressing.CiliumIPv6 `json:"ipv6"`               // Container IPv6 address.
	IPv4             addressing.CiliumIPv4 `json:"ipv4"`               // Container IPv4 address.
	IfIndex          int                   `json:"interface-index"`    // Host's interface index.
	NodeMAC          MAC                   `json:"node-mac"`           // Node MAC address.
	NodeIP           net.IP                `json:"node-ip"`            // Node IPv6 address.
	SecLabel         *SecCtxLabel          `json:"security-label"`     // Security Label  set to this endpoint.
	PortMap          []EPPortMap           `json:"port-mapping"`       // Port mapping used for this endpoint.
	Consumable       *Consumable           `json:"consumable"`
	PolicyMap        *policymap.PolicyMap  `json:"-"`
	Opts             *BoolOptions          `json:"options"` // Endpoint bpf options.
	Status           *EndpointStatus       `json:"status,omitempty"`
}

type statusLog struct {
	Status    Status    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

type EndpointStatus struct {
	Log     []*statusLog `json:"log,omitempty"`
	Index   int          `json:"index"`
	indexMU sync.RWMutex
}

func (e *EndpointStatus) lastIndex() int {
	lastIndex := e.Index - 1
	if lastIndex < 0 {
		return maxLogs - 1
	}
	return lastIndex
}

func (e *EndpointStatus) getAndIncIdx() int {
	idx := e.Index
	e.Index++
	if e.Index >= maxLogs {
		e.Index = 0
	}
	return idx
}

func (e *EndpointStatus) addStatusLog(s *statusLog) {
	idx := e.getAndIncIdx()
	if len(e.Log) < maxLogs {
		e.Log = append(e.Log, s)
	} else {
		e.Log[idx] = s
	}
}

func (e *EndpointStatus) String() string {
	e.indexMU.RLock()
	defer e.indexMU.RUnlock()
	if len(e.Log) > 0 {
		lastLog := e.Log[e.lastIndex()]
		if lastLog != nil {
			return fmt.Sprintf("%s", lastLog.Status.Code)
		}
	}
	return OK.String()
}

func (e *EndpointStatus) DumpLog() string {
	e.indexMU.RLock()
	defer e.indexMU.RUnlock()
	logs := []string{}
	for i := e.lastIndex(); ; i-- {
		if i < 0 {
			i = maxLogs - 1
		}
		if i < len(e.Log) && e.Log[i] != nil {
			logs = append(logs, fmt.Sprintf("%s - %s",
				e.Log[i].Timestamp.Format(time.RFC3339), e.Log[i].Status))
		}
		if i == e.Index {
			break
		}
	}
	if len(logs) == 0 {
		return OK.String()
	}
	return strings.Join(logs, "\n")
}

func (es *EndpointStatus) DeepCopy() *EndpointStatus {
	cpy := &EndpointStatus{}
	es.indexMU.RLock()
	defer es.indexMU.RUnlock()
	cpy.Index = es.Index
	cpy.Log = []*statusLog{}
	for _, v := range es.Log {
		cpy.Log = append(cpy.Log, v)
	}
	return cpy
}

func (e *Endpoint) DeepCopy() *Endpoint {
	cpy := &Endpoint{
		ID:               e.ID,
		DockerID:         e.DockerID,
		DockerNetworkID:  e.DockerNetworkID,
		DockerEndpointID: e.DockerEndpointID,
		IfName:           e.IfName,
		LXCMAC:           make(MAC, len(e.LXCMAC)),
		IPv6:             make(addressing.CiliumIPv6, len(e.IPv6)),
		IfIndex:          e.IfIndex,
		NodeMAC:          make(MAC, len(e.NodeMAC)),
		NodeIP:           make(net.IP, len(e.NodeIP)),
		PortMap:          make([]EPPortMap, len(e.PortMap)),
	}
	copy(cpy.LXCMAC, e.LXCMAC)
	copy(cpy.IPv6, e.IPv6)
	copy(cpy.NodeMAC, e.NodeMAC)
	copy(cpy.NodeIP, e.NodeIP)
	copy(cpy.PortMap, e.PortMap)

	if e.IPv4 != nil {
		cpy.IPv4 = make(addressing.CiliumIPv4, len(e.IPv4))
		copy(cpy.IPv4, e.IPv4)
	}
	if e.SecLabel != nil {
		cpy.SecLabel = e.SecLabel.DeepCopy()
	}
	if e.Consumable != nil {
		cpy.Consumable = e.Consumable.DeepCopy()
	}
	if e.PolicyMap != nil {
		cpy.PolicyMap = e.PolicyMap.DeepCopy()
	}
	if e.Opts != nil {
		cpy.Opts = e.Opts.DeepCopy()
	}
	if e.Status != nil {
		cpy.Status = e.Status.DeepCopy()
	}

	return cpy
}

// SetID sets the endpoint's host local unique ID.
func (e *Endpoint) SetID() {
	e.ID = e.IPv6.EndpointID()
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

// String returns endpoint on a JSON format.
func (e Endpoint) String() string {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func OptionChanged(key string, value bool, data interface{}) {
	e := data.(*Endpoint)
	switch key {
	case OptionConntrack:
		e.InvalidatePolicy()
	}
}

func (e *Endpoint) ApplyOpts(opts OptionMap) bool {
	// We want to be notified if the packets are dropped with the learn traffic
	if val, ok := opts[OptionLearnTraffic]; ok && val {
		opts[OptionDropNotify] = true
	}

	return e.Opts.Apply(opts, OptionChanged, e) > 0
}

func (ep *Endpoint) SetDefaultOpts(opts *BoolOptions) {
	if ep.Opts == nil {
		ep.Opts = NewBoolOptions(&EndpointOptionLibrary)
	}
	if ep.Opts.Library == nil {
		ep.Opts.Library = &EndpointOptionLibrary
	}

	if opts != nil {
		for k := range EndpointMutableOptionLibrary {
			ep.Opts.Set(k, opts.IsEnabled(k))
		}
		// Lets keep this here to prevent users to hurt themselves.
		ep.Opts.SetIfUnset(OptionLearnTraffic, false)
	}
}

type orderEndpoint func(e1, e2 *Endpoint) bool

// OrderEndpointAsc orders the slice of Endpoint in ascending ID order.
func OrderEndpointAsc(eps []Endpoint) {
	ascPriority := func(e1, e2 *Endpoint) bool {
		return e1.ID < e2.ID
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

// Return path to policy map of endpoint
func (e *Endpoint) PolicyMapPath() string {
	return common.PolicyMapPath + strconv.Itoa(int(e.ID))
}

// Return path to IPv6 connection tracking map of endpoint
func (e *Endpoint) Ct6MapPath() string {
	return common.BPFMapCT6 + strconv.Itoa(int(e.ID))
}

// Return path to IPv4 connection tracking map of endpoint
func (e *Endpoint) Ct4MapPath() string {
	return common.BPFMapCT4 + strconv.Itoa(int(e.ID))
}

func (e *Endpoint) InvalidatePolicy() {
	if e.Consumable != nil {
		// Resetting to 0 will trigger a regeneration on the next update
		log.Debugf("Invalidated policy for endpoint %s", e.ID)
		e.Consumable.Iteration = 0
	}
}

func (e *Endpoint) LogStatus(code StatusCode, msg string) {
	e.Status.indexMU.Lock()
	defer e.Status.indexMU.Unlock()
	sts := &statusLog{
		Status: Status{
			Code: code,
			Msg:  msg,
		},
		Timestamp: time.Now(),
	}
	e.Status.addStatusLog(sts)
}

func (e *Endpoint) LogStatusOK(msg string) {
	e.Status.indexMU.Lock()
	defer e.Status.indexMU.Unlock()
	sts := &statusLog{
		Status:    NewStatusOK(msg),
		Timestamp: time.Now(),
	}
	e.Status.addStatusLog(sts)
}
