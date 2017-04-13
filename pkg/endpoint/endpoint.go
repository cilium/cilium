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
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/op/go-logging"
)

var (
	//IPv4Enabled can be set to false to indicate IPv6 only operation
	IPv4Enabled = true
	log         = logging.MustGetLogger("cilium-endpoint")
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
		Verify: func(key string, val bool) error {
			if !IPv4Enabled {
				return fmt.Errorf("NAT46 requires IPv4 to be enabled")
			} else {
				return nil
			}
		},
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
	// StateCreating is used to set the endpoint is being created.
	StateCreating = string(models.EndpointStateCreating)
	// StateDisconnected is used to set the endpoint is disconnected.
	StateDisconnected = string(models.EndpointStateDisconnected)
	// StateWaitingForIdentity is used to set if the endpoint is waiting
	// for an identity from the KVStore.
	StateWaitingForIdentity = string(models.EndpointStateWaitingForIdentity)
	// StateReady specifies if the endpoint is read to be used.
	StateReady = string(models.EndpointStateReady)
	// StateRegenerating specifies when the endpoint is being regenerated.
	StateRegenerating = string(models.EndpointStateRegenerating)
)

// Endpoint contains all the details for a particular LXC and the host interface to where
// is connected to.
type Endpoint struct {
	ID               uint16                // Endpoint ID.
	Mutex            sync.RWMutex          // Protects all variables from this structure below this line
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
	// PolicyCalculated is true as soon as the policy has been calculated
	// for the first time
	PolicyCalculated bool
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
		Status:           NewEndpointStatus(),
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
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	currentState := models.EndpointState(e.State)
	if currentState == models.EndpointStateReady && e.Status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
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
		State:            currentState, // TODO: Validate
		Policy:           e.Consumable.GetModel(),
		Status:           e.Status.GetModel(),
		Addressing: &models.EndpointAddressing{
			IPV4: e.IPv4.String(),
			IPV6: e.IPv6.String(),
		},
	}
}

// statusLogMsg represents a log message.
type statusLogMsg struct {
	Status    Status    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// statusLog represents a slice of statusLogMsg.
type statusLog []*statusLogMsg

// componentStatus represents a map of a single statusLogMsg by StatusType.
type componentStatus map[StatusType]*statusLogMsg

// contains checks if the given `s` statusLogMsg is present in the
// priorityStatus.
func (ps componentStatus) contains(s *statusLogMsg) bool {
	return ps[s.Status.Type] == s
}

// statusTypeSlice represents a slice of StatusType, is used for sorting
// purposes.
type statusTypeSlice []StatusType

// Len returns the length of the slice.
func (p statusTypeSlice) Len() int { return len(p) }

// Less returns true if the element `j` is less than element `i`.
// *It's reversed* so that we can sort the slice by high to lowest priority.
func (p statusTypeSlice) Less(i, j int) bool { return p[i] > p[j] }

// Swap swaps element in `i` with element in `j`.
func (p statusTypeSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// sortByPriority returns a statusLog ordered from highest priority to lowest.
func (ps componentStatus) sortByPriority() statusLog {
	prs := statusTypeSlice{}
	for k := range ps {
		prs = append(prs, k)
	}
	sort.Sort(prs)
	slogSorted := statusLog{}
	for _, pr := range prs {
		slogSorted = append(slogSorted, ps[pr])
	}
	return slogSorted
}

// EndpointStatus represents the endpoint status.
type EndpointStatus struct {
	// CurrentStatuses is the last status of a given priority.
	CurrentStatuses componentStatus `json:"current-status,omitempty"`
	// Contains the last maxLogs messages for this endpoint.
	Log statusLog `json:"log,omitempty"`
	// Index is the index in the statusLog, is used to keep track the next
	// available position to write a new log message.
	Index int `json:"index"`
	// indexMU is the Mutex for the CurrentStatus and Log RW operations.
	indexMU sync.RWMutex
}

func NewEndpointStatus() *EndpointStatus {
	return &EndpointStatus{
		CurrentStatuses: componentStatus{},
		Log:             statusLog{},
	}
}

func (e *EndpointStatus) lastIndex() int {
	lastIndex := e.Index - 1
	if lastIndex < 0 {
		return maxLogs - 1
	}
	return lastIndex
}

// getAndIncIdx returns current free slot index and increments the index to the
// next index that can be overwritten.
func (e *EndpointStatus) getAndIncIdx() int {
	idx := e.Index
	e.Index++
	if e.Index >= maxLogs {
		e.Index = 0
	}
	// Lets skip the CurrentStatus message from the log to prevent removing
	// non-OK status!
	if e.Index < len(e.Log) &&
		e.CurrentStatuses.contains(e.Log[e.Index]) &&
		e.Log[e.Index].Status.Code != OK {
		e.Index++
		if e.Index >= maxLogs {
			e.Index = 0
		}
	}
	return idx
}

// addStatusLog adds statusLogMsg to endpoint log.
// example of e.Log's contents where maxLogs = 3 and Index = 0
// [index] - Priority - Code
// [0] - BPF - OK
// [1] - Policy - Failure
// [2] - BPF - OK
// With this log, the CurrentStatus will keep [1] for Policy priority and [2]
// for BPF priority.
//
// Whenever a new statusLogMsg is received, that log will be kept in the
// CurrentStatus map for the statusLogMsg's priority.
// The CurrentStatus map, ensures non of the failure messages are deleted for
// higher priority messages and vice versa.
func (e *EndpointStatus) addStatusLog(s *statusLogMsg) {
	e.CurrentStatuses[s.Status.Type] = s
	idx := e.getAndIncIdx()
	if len(e.Log) < maxLogs {
		e.Log = append(e.Log, s)
	} else {
		e.Log[idx] = s
	}
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

func (e *EndpointStatus) CurrentStatus() StatusCode {
	e.indexMU.RLock()
	defer e.indexMU.RUnlock()
	sP := e.CurrentStatuses.sortByPriority()
	for _, v := range sP {
		if v.Status.Code != OK {
			return v.Status.Code
		}
	}
	return OK
}

func (e *EndpointStatus) String() string {
	return e.CurrentStatus().String()
}

func (e *EndpointStatus) DeepCopy() *EndpointStatus {
	cpy := NewEndpointStatus()
	e.indexMU.RLock()
	defer e.indexMU.RUnlock()
	cpy.Index = e.Index
	cpy.Log = statusLog{}
	for _, v := range e.Log {
		cpy.Log = append(cpy.Log, v)
	}
	return cpy
}

func (e *Endpoint) DeepCopy() *Endpoint {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
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
		Status:           NewEndpointStatus(),
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

// StringIDLocked returns the endpoint's ID in a string. Must be called with
// the endpoint's mutex locked.
func (e *Endpoint) StringIDLocked() string {
	return strconv.Itoa(int(e.ID))
}

// SetID sets the endpoint's host local unique ID.
func (e *Endpoint) SetID() {
	e.Mutex.Lock()
	e.ID = e.IPv6.EndpointID()
	e.Mutex.Unlock()
}

func (e *Endpoint) GetIdentity() policy.NumericIdentity {
	if e.SecLabel != nil {
		return e.SecLabel.ID
	}

	return policy.InvalidIdentity
}

func (e *Endpoint) directoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d", e.ID))
}

func (e *Endpoint) Allows(id policy.NumericIdentity) bool {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	if e.Consumable != nil {
		return e.Consumable.Allows(id)
	}
	return false
}

// String returns endpoint on a JSON format.
func (e *Endpoint) String() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
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
		e.invalidatePolicy()
	}
}

// ApplyOptsLocked applies the given options to the endpoint's options and
// returns true if there were any options changed.
func (e *Endpoint) ApplyOptsLocked(opts map[string]string) bool {
	return e.Opts.Apply(opts, OptionChanged, e) > 0
}

func (e *Endpoint) SetDefaultOpts(opts *option.BoolOptions) {
	if e.Opts == nil {
		e.Opts = option.NewBoolOptions(&EndpointOptionLibrary)
	}
	if e.Opts.Library == nil {
		e.Opts.Library = &EndpointOptionLibrary
	}

	if opts != nil {
		for k := range EndpointMutableOptionLibrary {
			e.Opts.Set(k, opts.IsEnabled(k))
		}
	}
}

type orderEndpoint func(e1, e2 *models.Endpoint) bool

// OrderEndpointAsc orders the slice of Endpoint in ascending ID order.
func OrderEndpointAsc(eps []*models.Endpoint) {
	ascPriority := func(e1, e2 *models.Endpoint) bool {
		return e1.ID < e2.ID
	}
	orderEndpoint(ascPriority).sort(eps)
}

func (by orderEndpoint) sort(eps []*models.Endpoint) {
	dS := &epSorter{
		eps: eps,
		by:  by,
	}
	sort.Sort(dS)
}

type epSorter struct {
	eps []*models.Endpoint
	by  func(e1, e2 *models.Endpoint) bool
}

func (epS *epSorter) Len() int {
	return len(epS.eps)
}

func (epS *epSorter) Swap(i, j int) {
	epS.eps[i], epS.eps[j] = epS.eps[j], epS.eps[i]
}

func (epS *epSorter) Less(i, j int) bool {
	return epS.by(epS.eps[i], epS.eps[j])
}

// base64 returns the endpoint in a base64 format.
func (e *Endpoint) base64() (string, error) {
	var (
		jsonBytes []byte
		err       error
	)
	if e.Consumable != nil {
		e.Consumable.Mutex.RLock()
		jsonBytes, err = json.Marshal(e)
		e.Consumable.Mutex.RUnlock()
	} else {
		jsonBytes, err = json.Marshal(e)
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

// parseBase64ToEndpoint parses the endpoint stored in the given base64 string.
func parseBase64ToEndpoint(str string, ep *Endpoint) error {
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
	if err := parseBase64ToEndpoint(strEpSlice[1], &ep); err != nil {
		return nil, fmt.Errorf("failed to parse base64toendpoint: %s", err)
	}

	if ep.Status == nil {
		ep.Status = NewEndpointStatus()
	}

	return &ep, nil
}

// PolicyMapPath returns the path to policy map for endpoint ID.
func PolicyMapPath(id int) string {
	return bpf.MapPath(policymap.MapName + strconv.Itoa(id))
}

// PolicyMapPath returns the path to policy map of endpoint.
func (e *Endpoint) PolicyMapPathLocked() string {
	return PolicyMapPath(int(e.ID))
}

func Ct6MapPath(id int) string {
	return bpf.MapPath(ctmap.MapName6 + strconv.Itoa(id))
}

// Ct6MapPath returns the path to IPv6 connection tracking map of endpoint.
func (e *Endpoint) Ct6MapPathLocked() string {
	return Ct6MapPath(int(e.ID))
}

func Ct4MapPath(id int) string {
	return bpf.MapPath(ctmap.MapName4 + strconv.Itoa(id))
}

// Ct4MapPath returns the path to IPv4 connection tracking map of endpoint.
func (e *Endpoint) Ct4MapPathLocked() string {
	return Ct4MapPath(int(e.ID))
}

func (e *Endpoint) LogStatus(typ StatusType, code StatusCode, msg string) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	// FIXME instead of a mutex we could use a channel to send the status
	// log message to a single writer?
	e.Status.indexMU.Lock()
	defer e.Status.indexMU.Unlock()
	sts := &statusLogMsg{
		Status: Status{
			Code: code,
			Msg:  msg,
			Type: typ,
		},
		Timestamp: time.Now(),
	}
	e.Status.addStatusLog(sts)
}

func (e *Endpoint) LogStatusOK(typ StatusType, msg string) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	e.Status.indexMU.Lock()
	defer e.Status.indexMU.Unlock()
	sts := &statusLogMsg{
		Status:    NewStatusOK(typ, msg),
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

// Update modifies the endpoint options and regenerates the program.
func (e *Endpoint) Update(owner Owner, opts models.ConfigurationMap) error {
	e.Mutex.Lock()
	if err := e.Opts.Validate(opts); err != nil {
		e.Mutex.Unlock()
		return UpdateValidationError{err.Error()}
	}

	if opts != nil && !e.ApplyOptsLocked(opts) {
		e.Mutex.Unlock()
		// No changes have been applied, skip update
		return nil
	}
	e.Mutex.Unlock()

	// FIXME: restore previous configuration on failure
	e.Regenerate(owner)

	return nil
}

// LeaveLocked removes the endpoint's directory from the system. Must be called
// with Endpoint's mutex locked.
func (e *Endpoint) LeaveLocked(owner Owner) {
	owner.RemoveFromEndpointQueue(uint64(e.ID))
	if c := e.Consumable; c != nil {
		c.Mutex.RLock()
		if c.L4Policy != nil {
			// Passing a new map of nil will purge all redirects
			e.cleanUnusedRedirects(owner, c.L4Policy.Ingress, nil)
			e.cleanUnusedRedirects(owner, c.L4Policy.Egress, nil)
		}
		c.Mutex.RUnlock()
	}

	e.removeDirectory()
}

func (e *Endpoint) removeDirectory() {
	os.RemoveAll(e.directoryPath())
}

func (e *Endpoint) RemoveDirectory() {
	e.Mutex.Lock()
	e.removeDirectory()
	e.Mutex.Unlock()
}

func (e *Endpoint) CreateDirectory() error {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	lxcDir := e.directoryPath()
	if err := os.MkdirAll(lxcDir, 0777); err != nil {
		return fmt.Errorf("unable to create endpoint directory: %s", err)
	}

	return nil
}

func (e *Endpoint) RegenerateIfReady(owner Owner) error {
	e.Mutex.RLock()
	if e.State != StateReady && e.State != StateWaitingForIdentity {
		e.Mutex.RUnlock()
		return nil
	}
	e.Mutex.RUnlock()

	// TODO: Should we change RegenerateIfReady to block/non-block like
	// e.Regenerate?
	e.Regenerate(owner)
	return nil
}
