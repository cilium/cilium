// Copyright 2016-2017 Authors of Cilium
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

package endpoint

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/bpf/ctmap"
	"github.com/cilium/cilium/bpf/policymap"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-endpoint")
)

// PortMap is the port mapping representation for a particular endpoint.
type PortMap struct {
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
	OptionNAT46               = "NAT46"
	OptionPolicy              = "Policy"

	maxLogs = 256
)

var (
	OptionSpecAllowToHost = option.Option{
		Define:      "ALLOW_TO_HOST",
		Immutable:   true,
		Description: "Allow all traffic to local host",
	}

	OptionSpecAllowToWorld = option.Option{
		Define:      "ALLOW_TO_WORLD",
		Immutable:   true,
		Description: "Allow all traffic to outside world",
	}

	OptionSpecConntrackAccounting = option.Option{
		Define:      "CONNTRACK_ACCOUNTING",
		Description: "Enable per flow (conntrack) statistics",
		Requires:    []string{OptionConntrack},
	}

	OptionSpecConntrack = option.Option{
		Define:      "CONNTRACK",
		Description: "Enable stateful connection tracking",
	}

	OptionSpecDebug = option.Option{
		Define:      "DEBUG",
		Description: "Enable debugging trace statements",
	}

	OptionSpecDropNotify = option.Option{
		Define:      "DROP_NOTIFY",
		Description: "Enable drop notifications",
	}

	OptionSpecNAT46 = option.Option{
		Define:      "ENABLE_NAT46",
		Description: "Enable automatic NAT46 translation",
		Requires:    []string{OptionConntrack},
	}

	OptionSpecPolicy = option.Option{
		Define:      "POLICY_ENFORCEMENT",
		Description: "Enable policy enforcement",
	}

	EndpointMutableOptionLibrary = option.OptionLibrary{
		OptionConntrackAccounting: &OptionSpecConntrackAccounting,
		OptionConntrack:           &OptionSpecConntrack,
		OptionDebug:               &OptionSpecDebug,
		OptionDropNotify:          &OptionSpecDropNotify,
		OptionNAT46:               &OptionSpecNAT46,
		OptionPolicy:              &OptionSpecPolicy,
	}

	EndpointOptionLibrary = option.OptionLibrary{
		OptionAllowToHost:  &OptionSpecAllowToHost,
		OptionAllowToWorld: &OptionSpecAllowToWorld,
	}
)

func init() {
	for k, v := range EndpointMutableOptionLibrary {
		EndpointOptionLibrary[k] = v
	}
}

const (
	StateCreating           = string(models.EndpointStateCreating)
	StateDisconnected       = string(models.EndpointStateDisconnected)
	StateWaitingForIdentity = string(models.EndpointStateWaitingForIdentity)
	StateReady              = string(models.EndpointStateReady)
)

// Endpoint contains all the details for a particular LXC and the host interface to where
// is connected to.
type Endpoint struct {
	ID               uint16                // Endpoint ID.
	DockerID         string                // Docker ID.
	DockerNetworkID  string                // Docker network ID.
	DockerEndpointID string                // Docker endpoint ID.
	IfName           string                // Container's interface name.
	LXCMAC           mac.MAC               // Container MAC address.
	IPv6             addressing.CiliumIPv6 // Container IPv6 address.
	IPv4             addressing.CiliumIPv4 // Container IPv4 address.
	IfIndex          int                   // Host's interface index.
	NodeMAC          mac.MAC               // Node MAC address.
	NodeIP           net.IP                // Node IPv6 address.
	SecLabel         *policy.Identity      // Security Label  set to this endpoint.
	PortMap          []PortMap             // Port mapping used for this endpoint.
	Consumable       *policy.Consumable
	PolicyMap        *policymap.PolicyMap
	Opts             *option.BoolOptions // Endpoint bpf options.
	Status           *EndpointStatus
	State            string
}

func NewEndpointFromChangeModel(base *models.EndpointChangeRequest) (*Endpoint, error) {
	if base == nil {
		return nil, nil
	}

	ep := &Endpoint{
		ID:               uint16(base.ID),
		DockerID:         base.ContainerID,
		DockerNetworkID:  base.DockerNetworkID,
		DockerEndpointID: base.DockerEndpointID,
		IfName:           base.InterfaceName,
		IfIndex:          int(base.InterfaceIndex),
		State:            string(base.State),
	}

	if base.Mac != "" {
		m, err := mac.ParseMAC(base.Mac)
		if err != nil {
			return nil, err
		}
		ep.LXCMAC = m
	}

	if base.HostMac != "" {
		m, err := mac.ParseMAC(base.HostMac)
		if err != nil {
			return nil, err
		}
		ep.NodeMAC = m
	}

	if base.Addressing != nil {
		if ip := base.Addressing.IPV6; ip != "" {
			ip6, err := addressing.NewCiliumIPv6(ip)
			if err != nil {
				return nil, err
			}
			ep.IPv6 = ip6
		}

		if ip := base.Addressing.IPV4; ip != "" {
			ip4, err := addressing.NewCiliumIPv4(ip)
			if err != nil {
				return nil, err
			}
			ep.IPv4 = ip4
		}
	}

	return ep, nil
}

func (e *Endpoint) GetModel() *models.Endpoint {
	if e == nil {
		return nil
	}

	return &models.Endpoint{
		ID:               int64(e.ID),
		ContainerID:      e.DockerID,
		DockerEndpointID: e.DockerEndpointID,
		DockerNetworkID:  e.DockerNetworkID,
		Identity:         e.SecLabel.GetModel(),
		InterfaceIndex:   int64(e.IfIndex),
		InterfaceName:    e.IfName,
		Mac:              e.LXCMAC.String(),
		HostMac:          e.NodeMAC.String(),
		State:            models.EndpointState(e.State), // TODO: Validate
		Policy:           e.Consumable.GetModel(),
		Status:           e.Status.GetModel(),
		Addressing: &models.EndpointAddressing{
			IPV4: e.IPv4.String(),
			IPV6: e.IPv6.String(),
		},
	}
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

func (e *EndpointStatus) GetModel() []*models.EndpointStatusChange {
	e.indexMU.RLock()
	defer e.indexMU.RUnlock()

	list := []*models.EndpointStatusChange{}
	for i := e.lastIndex(); ; i-- {
		if i < 0 {
			i = maxLogs - 1
		}
		if i < len(e.Log) && e.Log[i] != nil {
			list = append(list, &models.EndpointStatusChange{
				Timestamp: e.Log[i].Timestamp.Format(time.RFC3339),
				Code:      e.Log[i].Status.Code.String(),
				Message:   e.Log[i].Status.Msg,
			})
		}
		if i == e.Index {
			break
		}
	}

	return list
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
		LXCMAC:           make(mac.MAC, len(e.LXCMAC)),
		IPv6:             make(addressing.CiliumIPv6, len(e.IPv6)),
		IfIndex:          e.IfIndex,
		NodeMAC:          make(mac.MAC, len(e.NodeMAC)),
		NodeIP:           make(net.IP, len(e.NodeIP)),
		PortMap:          make([]PortMap, len(e.PortMap)),
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

func (e *Endpoint) StringID() string {
	return strconv.Itoa(int(e.ID))
}

// SetID sets the endpoint's host local unique ID.
func (e *Endpoint) SetID() {
	e.ID = e.IPv6.EndpointID()
}

func (e *Endpoint) DirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d", e.ID))
}

func (e *Endpoint) Allows(id policy.NumericIdentity) bool {
	if e.Consumable != nil {
		return e.Consumable.Allows(id)
	}
	return false
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

func (e *Endpoint) ApplyOpts(opts map[string]string) bool {
	return e.Opts.Apply(opts, OptionChanged, e) > 0
}

func (ep *Endpoint) SetDefaultOpts(opts *option.BoolOptions) {
	if ep.Opts == nil {
		ep.Opts = option.NewBoolOptions(&EndpointOptionLibrary)
	}
	if ep.Opts.Library == nil {
		ep.Opts.Library = &EndpointOptionLibrary
	}

	if opts != nil {
		for k := range EndpointMutableOptionLibrary {
			ep.Opts.Set(k, opts.IsEnabled(k))
		}
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

// Return path to policy map for endpoint ID
func PolicyMapPath(id int) string {
	return bpf.MapPath(policymap.MapName + strconv.Itoa(id))
}

// Return path to policy map of endpoint
func (e *Endpoint) PolicyMapPath() string {
	return PolicyMapPath(int(e.ID))
}

func Ct6MapPath(id int) string {
	return bpf.MapPath(ctmap.MapName6 + strconv.Itoa(id))
}

// Return path to IPv6 connection tracking map of endpoint
func (e *Endpoint) Ct6MapPath() string {
	return Ct6MapPath(int(e.ID))
}

func Ct4MapPath(id int) string {
	return bpf.MapPath(ctmap.MapName4 + strconv.Itoa(id))
}

// Return path to IPv4 connection tracking map of endpoint
func (e *Endpoint) Ct4MapPath() string {
	return Ct4MapPath(int(e.ID))
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

type UpdateValidationError struct {
	msg string
}

func (e UpdateValidationError) Error() string { return e.msg }

type UpdateCompilationError struct {
	msg string
}

func (e UpdateCompilationError) Error() string { return e.msg }

// Updates the endpoint options and regenerates the program
func (e *Endpoint) Update(owner Owner, opts models.ConfigurationMap) error {
	if err := e.Opts.Validate(opts); err != nil {
		return UpdateValidationError{err.Error()}
	}

	if opts != nil && !e.ApplyOpts(opts) {
		// No changes have been applied, skip update
		return nil
	}

	// FIXME: restore previous configuration on failure
	if err := e.regenerateLocked(owner); err != nil {
		return UpdateCompilationError{err.Error()}
	}

	return nil
}

func (e *Endpoint) Leave(owner Owner) {
	e.RemoveDirectory()
}

func (e *Endpoint) RemoveDirectory() {
	os.RemoveAll(e.DirectoryPath())
}

func (e *Endpoint) CreateDirectory() error {
	lxcDir := e.DirectoryPath()
	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		return fmt.Errorf("unable to create endpoint directory: %s", err)
	}

	return nil
}

func (e *Endpoint) RegenerateIfReady(owner Owner) error {
	if e.State != StateReady {
		return nil
	}

	return e.Regenerate(owner)
}
