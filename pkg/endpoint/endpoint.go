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
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/sirupsen/logrus"
)

var (
	//IPv4Enabled can be set to false to indicate IPv6 only operation
	IPv4Enabled = true
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
	OptionConntrackLocal      = "ConntrackLocal"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDropNotify          = "DropNotification"
	OptionTraceNotify         = "TraceNotification"
	OptionNAT46               = "NAT46"
	OptionIngressPolicy       = "IngressPolicy"
	OptionEgressPolicy        = "EgressPolicy"
	AlwaysEnforce             = "always"
	NeverEnforce              = "never"
	DefaultEnforcement        = "default"

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

	OptionSpecConntrackLocal = option.Option{
		Define:      "CONNTRACK_LOCAL",
		Description: "Use endpoint dedicated tracking table instead of global one",
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

	OptionSpecTraceNotify = option.Option{
		Define:      "TRACE_NOTIFY",
		Description: "Enable trace notifications",
	}

	OptionSpecNAT46 = option.Option{
		Define:      "ENABLE_NAT46",
		Description: "Enable automatic NAT46 translation",
		Requires:    []string{OptionConntrack},
		Verify: func(key string, val bool) error {
			if !IPv4Enabled {
				return fmt.Errorf("NAT46 requires IPv4 to be enabled")
			}
			return nil
		},
	}

	OptionIngressSpecPolicy = option.Option{
		Define:      "POLICY_INGRESS",
		Description: "Enable ingress policy enforcement",
	}

	OptionEgressSpecPolicy = option.Option{
		Define:      "POLICY_EGRESS",
		Description: "Enable egress policy enforcement",
	}

	EndpointMutableOptionLibrary = option.OptionLibrary{
		OptionConntrackAccounting: &OptionSpecConntrackAccounting,
		OptionConntrackLocal:      &OptionSpecConntrackLocal,
		OptionConntrack:           &OptionSpecConntrack,
		OptionDebug:               &OptionSpecDebug,
		OptionDropNotify:          &OptionSpecDropNotify,
		OptionTraceNotify:         &OptionSpecTraceNotify,
		OptionNAT46:               &OptionSpecNAT46,
		OptionIngressPolicy:       &OptionIngressSpecPolicy,
		OptionEgressPolicy:        &OptionEgressSpecPolicy,
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

	// StateWaitingForIdentity is used to set if the endpoint is waiting
	// for an identity from the KVStore.
	StateWaitingForIdentity = string(models.EndpointStateWaitingForIdentity)

	// StateReady specifies if the endpoint is ready to be used.
	StateReady = string(models.EndpointStateReady)

	// StateWaitingToRegenerate specifies when the endpoint needs to be regenerated, but regeneration has not started yet.
	StateWaitingToRegenerate = string(models.EndpointStateWaitingToRegenerate)

	// StateRegenerating specifies when the endpoint is being regenerated.
	StateRegenerating = string(models.EndpointStateRegenerating)

	// StateDisconnecting indicates that the endpoint is being disconnected
	StateDisconnecting = string(models.EndpointStateDisconnecting)

	// StateDisconnected is used to set the endpoint is disconnected.
	StateDisconnected = string(models.EndpointStateDisconnected)

	// StateRestoring is used to set the endpoint is being restored.
	StateRestoring = string(models.EndpointStateRestoring)

	// CallsMapName specifies the base prefix for EP specific call map.
	CallsMapName = "cilium_calls_"
	// PolicyGlobalMapName specifies the global tail call map for EP handle_policy() lookup.
	PolicyGlobalMapName = "cilium_policy"
)

// LabelsMap holds mapping from numeric policy identity to labels
type LabelsMap map[policy.NumericIdentity]pkgLabels.LabelArray

// Endpoint represents a container or similar which can be individually
// addresses on L3 with its own IP addresses. This structured is managed by the
// endpoint manager in pkg/endpointmanager.
//
// This structure is written as JSON to StateDir/{ID}/lxc_config.h to allow to
// restore endpoints when the agent is being restarted. The restore operation
// will read the file and re-create all endpoints with all fields which are not
// marked as private to JSON marshal.
type Endpoint struct {
	// ID of the endpoint, unique in the scope of the node
	ID uint16

	// Mutex protects write operations to this endpoint structure
	Mutex lock.RWMutex

	// ContainerName is the name given to the endpoint by the container runtime
	ContainerName string

	// DockerID is the container ID that containerd has assigned to the endpoint
	//
	// FIXME: Rename this field to ContainerID
	DockerID string

	// DockerNetworkID is the network ID of the libnetwork network if the
	// endpoint is a docker managed container which uses libnetwork
	DockerNetworkID string

	// DockerEndpointID is the Docker network endpoint ID if managed by
	// libnetwork
	DockerEndpointID string

	// IfName is the name of the host facing interface (veth pair) which
	// connects into the endpoint
	IfName string

	// IfIndex is the interface index of the host face interface (veth pair)
	IfIndex int

	// OpLabels is the endpoint's label configuration
	//
	// FIXME: Rename this field to Labels
	OpLabels pkgLabels.OpLabels

	// LXCMAC is the MAC address of the endpoint
	//
	// FIXME: Rename this field to MAC
	LXCMAC mac.MAC // Container MAC address.

	// IPv6 is the IPv6 address of the endpoint
	IPv6 addressing.CiliumIPv6

	// IPv4 is the IPv4 address of the endpoint
	IPv4 addressing.CiliumIPv4

	// NodeMAC is the MAC of the node (agent). The MAC is different for every endpoint.
	NodeMAC mac.MAC

	// SecLabel is (L3) the identity of this endpoint
	//
	// FIXME: Rename this field to Identity
	SecLabel *policy.Identity // Security Label  set to this endpoint.

	// LabelsHash is a SHA256 hash over the SecLabel labels
	LabelsHash string

	// LabelsMap is the Set of all security labels used in the last policy computation
	LabelsMap *LabelsMap

	// PortMap is port mapping configuration of the endpoint
	PortMap []PortMap // Port mapping used for this endpoint.

	// Consumable is the list of allowed consumers of this endpoint. This
	// is populated based on the policy.
	Consumable *policy.Consumable `json:"-"`

	// L4Policy is the L4Policy in effect for the
	// endpoint. Normally it is the same as the Consumable's
	// L4Policy, but this is needed during policy recalculation to
	// be able to clean up PolicyMap after consumable has already
	// been updated.
	L4Policy *policy.L4Policy `json:"-"`

	// PolicyMap is the policy related state of the datapath including
	// reference to all policy related BPF
	PolicyMap *policymap.PolicyMap `json:"-"`

	// L3Policy is the CIDR based policy configuration of the endpoint
	L3Policy *policy.L3Policy `json:"-"`

	// L3Maps is the datapath representation of L3Policy
	L3Maps L3Maps `json:"-"`

	// Opts are configurable boolean options
	Opts *option.BoolOptions

	// Status are the last n state transitions this endpoint went through
	Status *EndpointStatus

	// state is the state the endpoint is in. See SetStateLocked()
	state string

	// PolicyCalculated is true as soon as the policy has been calculated
	// for the first time. As long as this value is false, all packets sent
	// by the endpoint will be dropped to ensure that the endpoint cannot
	// bypass policy while it is still being resolved.
	PolicyCalculated bool `json:"-"`

	// PodName is the name of the Kubernetes pod if the endpoint is managed
	// by Kubernetes
	PodName string

	// policyRevision is the policy revision this endpoint is currently on
	policyRevision uint64

	// nextPolicyRevision is the policy revision that the endpoint has
	// updated to and that will become effective with the next regenerate
	nextPolicyRevision uint64

	// forcePolicyCompute full endpoint policy recomputation
	// Set when endpoint options have been changed. Cleared right before releasing the
	// endpoint mutex after policy recalculation.
	forcePolicyCompute bool

	// BuildMutex synchronizes builds of individual endpoints and locks out
	// deletion during builds
	//
	// FIXME: Mark private once endpoint deletion can be moved into
	// `pkg/endpoint`
	BuildMutex lock.Mutex

	// logger is a logrus object with fields set to report an endpoints information.
	// You must hold Endpoint.Mutex to read or write it (but not to log with it).
	logger *logrus.Entry
}

// NewEndpointWithState creates a new endpoint useful for testing purposes
func NewEndpointWithState(ID uint16, state string) *Endpoint {
	return &Endpoint{
		ID:     ID,
		Opts:   option.NewBoolOptions(&EndpointOptionLibrary),
		Status: NewEndpointStatus(),
		state:  state,
	}
}

// NewEndpointFromChangeModel creates a new endpoint from a request
func NewEndpointFromChangeModel(base *models.EndpointChangeRequest, l pkgLabels.Labels) (*Endpoint, error) {
	if base == nil {
		return nil, nil
	}

	ep := &Endpoint{
		ID:               uint16(base.ID),
		ContainerName:    base.ContainerName,
		DockerID:         base.ContainerID,
		DockerNetworkID:  base.DockerNetworkID,
		DockerEndpointID: base.DockerEndpointID,
		IfName:           base.InterfaceName,
		IfIndex:          int(base.InterfaceIndex),
		OpLabels: pkgLabels.OpLabels{
			Custom:                pkgLabels.Labels{},
			Disabled:              pkgLabels.Labels{},
			OrchestrationIdentity: l.DeepCopy(),
			OrchestrationInfo:     pkgLabels.Labels{},
		},
		state:  string(base.State),
		Status: NewEndpointStatus(),
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

// GetModelRLocked returns the API model of endpoint e.
// e.Mutex must be RLocked.
func (e *Endpoint) GetModelRLocked() *models.Endpoint {
	policy := models.EndpointPolicyEnabledNone
	if e == nil {
		return nil
	}

	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.Status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
	}

	policyIngressEnabled := e.Opts.IsEnabled(OptionIngressPolicy)
	policyEgressEnabled := e.Opts.IsEnabled(OptionEgressPolicy)

	if policyIngressEnabled && policyEgressEnabled {
		policy = models.EndpointPolicyEnabledBoth
	} else if policyIngressEnabled {
		policy = models.EndpointPolicyEnabledIngress
	} else if policyEgressEnabled {
		policy = models.EndpointPolicyEnabledEgress
	}

	// This returns the most recent log entry for this endpoint. It is backwards
	// compatible with the json from before we added `cilium endpoint log` but it
	// only returns 1 entry.
	statusLog := e.Status.GetModel()
	if len(statusLog) > 0 {
		statusLog = statusLog[:1]
	}

	return &models.Endpoint{
		ID:               int64(e.ID),
		ContainerID:      e.DockerID,
		ContainerName:    e.ContainerName,
		DockerEndpointID: e.DockerEndpointID,
		DockerNetworkID:  e.DockerNetworkID,
		Identity:         e.SecLabel.GetModel(),
		InterfaceIndex:   int64(e.IfIndex),
		InterfaceName:    e.IfName,
		Labels: &models.LabelConfiguration{
			Custom:                e.OpLabels.Custom.GetModel(),
			OrchestrationIdentity: e.OpLabels.OrchestrationIdentity.GetModel(),
			OrchestrationInfo:     e.OpLabels.OrchestrationInfo.GetModel(),
			Disabled:              e.OpLabels.Disabled.GetModel(),
		},
		Mac:            e.LXCMAC.String(),
		HostMac:        e.NodeMAC.String(),
		PodName:        e.PodName,
		State:          currentState, // TODO: Validate
		Status:         statusLog,
		Health:         e.getHealthModel(),
		Policy:         e.GetPolicyModel(),
		PolicyEnabled:  &policy,
		PolicyRevision: int64(e.policyRevision),
		Addressing: &models.EndpointAddressing{
			IPV4: e.IPv4.String(),
			IPV6: e.IPv6.String(),
		},
	}
}

// GetHealthModel returns the endpoint's health object.
//
// Must be called with e.Mutex locked.
func (e *Endpoint) getHealthModel() *models.EndpointHealth {
	// Duplicated from GetModelRLocked.
	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.Status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
	}

	h := models.EndpointHealth{
		Bpf:           models.EndpointHealthStatusDisabled,
		Policy:        models.EndpointHealthStatusDisabled,
		Connected:     false,
		OverallHealth: models.EndpointHealthStatusDisabled,
	}
	switch currentState {
	case models.EndpointStateRegenerating, models.EndpointStateWaitingToRegenerate, models.EndpointStateDisconnecting:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusPending,
			Policy:        models.EndpointHealthStatusPending,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusPending,
		}
	case models.EndpointStateCreating:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusBootstrap,
			Policy:        models.EndpointHealthStatusDisabled,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusDisabled,
		}
	case models.EndpointStateWaitingForIdentity:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusDisabled,
			Policy:        models.EndpointHealthStatusBootstrap,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusDisabled,
		}
	case models.EndpointStateNotReady:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusWarning,
			Policy:        models.EndpointHealthStatusWarning,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusWarning,
		}
	case models.EndpointStateDisconnected:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusDisabled,
			Policy:        models.EndpointHealthStatusDisabled,
			Connected:     false,
			OverallHealth: models.EndpointHealthStatusDisabled,
		}
	case models.EndpointStateReady:
		h = models.EndpointHealth{
			Bpf:           models.EndpointHealthStatusOK,
			Policy:        models.EndpointHealthStatusOK,
			Connected:     true,
			OverallHealth: models.EndpointHealthStatusOK,
		}
	}

	return &h
}

// GetHealthModel returns the endpoint's health object.
func (e *Endpoint) GetHealthModel() *models.EndpointHealth {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	return e.getHealthModel()
}

// GetModel returns the API model of endpoint e.
func (e *Endpoint) GetModel() *models.Endpoint {
	if e == nil {
		return nil
	}
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	return e.GetModelRLocked()
}

// GetPolicyModel returns the endpoint's policy as an API model.
//
// Must be called with e.Mutex locked.
func (e *Endpoint) GetPolicyModel() *models.EndpointPolicy {
	if e == nil {
		return nil
	}

	if e.Consumable == nil {
		return nil
	}

	e.Consumable.Mutex.RLock()
	defer e.Consumable.Mutex.RUnlock()

	consumers := []int64{}
	for _, v := range e.Consumable.Consumers {
		consumers = append(consumers, int64(v.ID))
	}

	return &models.EndpointPolicy{
		ID:               int64(e.Consumable.ID),
		Build:            int64(e.Consumable.Iteration),
		AllowedConsumers: consumers,
		CidrPolicy:       e.L3Policy.GetModel(),
		L4:               e.Consumable.L4Policy.GetModel(),
	}
}

// GetID returns the endpoint's ID
func (e *Endpoint) GetID() uint64 {
	return uint64(e.ID)
}

// RLock locks the endpoint for reading
func (e *Endpoint) RLock() {
	e.Mutex.RLock()
}

// RUnlock unlocks the endpoint after reading
func (e *Endpoint) RUnlock() {
	e.Mutex.RUnlock()
}

// Lock locks the endpoint for reading  or writing
func (e *Endpoint) Lock() {
	e.Mutex.Lock()
}

// Unlock unlocks the endpoint after reading or writing
func (e *Endpoint) Unlock() {
	e.Mutex.Unlock()
}

// GetLabels returns the labels as slice
func (e *Endpoint) GetLabels() []string {
	if e.SecLabel == nil {
		return []string{}
	}

	return e.SecLabel.Labels.GetModel()
}

// GetLabelsSHA returns the SHA of labels
func (e *Endpoint) GetLabelsSHA() string {
	if e.SecLabel == nil {
		return ""
	}

	e.SecLabel.LabelsSHA256 = e.SecLabel.Labels.SHA256Sum()

	return e.SecLabel.LabelsSHA256
}

// GetIPv4Address returns the IPv4 address of the endpoint
func (e *Endpoint) GetIPv4Address() string {
	return e.IPv4.String()
}

// GetIPv6Address returns the IPv6 address of the endpoint
func (e *Endpoint) GetIPv6Address() string {
	return e.IPv6.String()
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
	indexMU lock.RWMutex
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
				State:     models.EndpointState(e.Log[i].Status.State),
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

// StringID returns the endpoint's ID in a string.
func (e *Endpoint) StringID() string {
	return strconv.Itoa(int(e.ID))
}

func (e *Endpoint) GetIdentity() policy.NumericIdentity {
	if e.SecLabel != nil {
		return e.SecLabel.ID
	}

	return policy.InvalidIdentity
}

// ResolveIdentity fetches Consumable from consumable cache, using security identity as key.
func (e *Endpoint) ResolveIdentity(srcIdentity policy.NumericIdentity) *policy.Identity {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	return e.Consumable.ResolveIdentityFromCache(srcIdentity)
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

// optionChanged is a callback used with pkg/option to apply the options to an
// endpoint.  Not used for anything at the moment.
func optionChanged(key string, value bool, data interface{}) {
}

// applyOptsLocked applies the given options to the endpoint's options and
// returns true if there were any options changed.
func (e *Endpoint) applyOptsLocked(opts map[string]string) bool {
	return e.Opts.Apply(opts, optionChanged, e) > 0
}

// ForcePolicyCompute marks the endpoint for forced bpf regeneration.
func (e *Endpoint) ForcePolicyCompute() {
	e.forcePolicyCompute = true
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

	ep.state = StateRestoring

	return &ep, nil
}

func (e *Endpoint) RemoveFromGlobalPolicyMap() error {
	gpm, err := policymap.OpenGlobalMap(e.PolicyGlobalMapPathLocked())
	if err == nil {
		// We need to remove ourselves from global map, so that
		// resources (prog/map reference counts) can be released.
		gpm.DeleteConsumer(uint32(e.ID))
		gpm.Close()
	}

	return err
}

// GetBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func (e *Endpoint) GetBPFKeys() []lxcmap.EndpointKey {
	key := lxcmap.NewEndpointKey(e.IPv6.IP())

	if e.IPv4 != nil {
		key4 := lxcmap.NewEndpointKey(e.IPv4.IP())
		return []lxcmap.EndpointKey{key, key4}
	}

	return []lxcmap.EndpointKey{key}
}

// GetBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
func (e *Endpoint) GetBPFValue() (*lxcmap.EndpointInfo, error) {
	mac, err := e.LXCMAC.Uint64()
	if err != nil {
		return nil, err
	}

	nodeMAC, err := e.NodeMAC.Uint64()
	if err != nil {
		return nil, err
	}

	info := &lxcmap.EndpointInfo{
		IfIndex: uint32(e.IfIndex),
		// Store security label in network byte order so it can be
		// written into the packet without an additional byte order
		// conversion.
		SecLabelID: byteorder.HostToNetwork(uint16(e.GetIdentity())).(uint16),
		LxcID:      e.ID,
		MAC:        lxcmap.MAC(mac),
		NodeMAC:    lxcmap.MAC(nodeMAC),
	}

	for i, pM := range e.PortMap {
		info.PortMap[i] = lxcmap.PortMap{
			From: byteorder.HostToNetwork(pM.From).(uint16),
			To:   byteorder.HostToNetwork(pM.To).(uint16),
		}
	}

	return info, nil
}

// mapPath returns the path to a map for endpoint ID.
func mapPath(mapname string, id int) string {
	return bpf.MapPath(mapname + strconv.Itoa(id))
}

// PolicyMapPathLocked returns the path to policy map of endpoint.
func (e *Endpoint) PolicyMapPathLocked() string {
	return mapPath(policymap.MapName, int(e.ID))
}

// IPv6IngressMapPathLocked returns the path to policy map of endpoint.
func (e *Endpoint) IPv6IngressMapPathLocked() string {
	return mapPath(cidrmap.MapName+"ingress6_", int(e.ID))
}

// IPv6EgressMapPathLocked returns the path to policy map of endpoint.
func (e *Endpoint) IPv6EgressMapPathLocked() string {
	return mapPath(cidrmap.MapName+"egress6_", int(e.ID))
}

// IPv4IngressMapPathLocked returns the path to policy map of endpoint.
func (e *Endpoint) IPv4IngressMapPathLocked() string {
	return mapPath(cidrmap.MapName+"ingress4_", int(e.ID))
}

// IPv4EgressMapPathLocked returns the path to policy map of endpoint.
func (e *Endpoint) IPv4EgressMapPathLocked() string {
	return mapPath(cidrmap.MapName+"egress4_", int(e.ID))
}

// PolicyGlobalMapPathLocked returns the path to the global policy map.
func (e *Endpoint) PolicyGlobalMapPathLocked() string {
	return bpf.MapPath(PolicyGlobalMapName)
}

func CallsMapPath(id int) string {
	return bpf.MapPath(CallsMapName + strconv.Itoa(id))
}

// CallsMapPathLocked returns the path to cilium tail calls map of an endpoint.
func (e *Endpoint) CallsMapPathLocked() string {
	return CallsMapPath(int(e.ID))
}

// Ct6MapPath returns the path to IPv6 connection tracking map of endpoint.
func Ct6MapPath(id int) string {
	return bpf.MapPath(ctmap.MapName6 + strconv.Itoa(id))
}

func (e *Endpoint) Ct6MapPathLocked() string {
	return Ct6MapPath(int(e.ID))
}

// Ct4MapPath returns the path to IPv4 connection tracking map of endpoint.
func Ct4MapPath(id int) string {
	return bpf.MapPath(ctmap.MapName4 + strconv.Itoa(id))
}

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
	e.logStatusLocked(typ, code, msg)
}

func (e *Endpoint) LogStatusOK(typ StatusType, msg string) {
	e.LogStatus(typ, OK, msg)
}

func (e *Endpoint) logStatusLocked(typ StatusType, code StatusCode, msg string) {
	sts := &statusLogMsg{
		Status: Status{
			Code:  code,
			Msg:   msg,
			Type:  typ,
			State: e.state,
		},
		Timestamp: time.Now().UTC(),
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
	if opts == nil {
		return nil
	}

	e.Mutex.Lock()
	if err := e.Opts.Validate(opts); err != nil {
		e.Mutex.Unlock()
		return UpdateValidationError{err.Error()}
	}

	// Option changes may be overridden by the policy configuration.
	// Currently we return all-OK even in that case.
	changed, ctCleaned, err := e.TriggerPolicyUpdatesLocked(owner, opts)
	if err != nil {
		e.Mutex.Unlock()
		ctCleaned.Wait()
		return UpdateCompilationError{err.Error()}
	}

	if changed {
		changed = e.SetStateLocked(StateWaitingToRegenerate, "Updated endpoint options; policy changes apply to this endpoint")
	}
	e.Mutex.Unlock()
	ctCleaned.Wait()

	if changed {
		e.Regenerate(owner, "updated endpoint options & policy changes apply to this endpoint")
	}

	return nil
}

// HasLabels returns whether endpoint e contains all labels l. Will return 'false'
// if any label in l is not in the endpoint's labels.
func (e *Endpoint) HasLabels(l pkgLabels.Labels) bool {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	allEpLabels := e.OpLabels.AllLabels()

	for _, v := range l {
		found := false
		for _, j := range allEpLabels {
			if j.Equals(v) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// UpdateOrchInformationLabels updates orchestration labels for the endpoint which
// are not used in determining the security identity for the endpoint.
func (e *Endpoint) UpdateOrchInformationLabels(l pkgLabels.Labels) {
	e.Mutex.Lock()
	for k, v := range l {
		tmp := v.DeepCopy()
		e.getLogger().WithField(logfields.Labels, logfields.Repr(tmp)).Debug("Assigning orchestration information label")
		e.OpLabels.OrchestrationInfo[k] = tmp
	}
	e.Mutex.Unlock()
}

// UpdateOrchIdentityLabels updates orchestration labels for the endpoint which
// are used in determining the security identity for the endpoint.
//
// Note: Must be called with endpoint.Mutex held!
func (e *Endpoint) UpdateOrchIdentityLabels(l pkgLabels.Labels) bool {
	e.Mutex.Lock()
	changed := false

	e.OpLabels.OrchestrationIdentity.MarkAllForDeletion()
	e.OpLabels.Disabled.MarkAllForDeletion()

	for k, v := range l {
		switch {
		case e.OpLabels.Disabled[k] != nil:
			e.OpLabels.Disabled[k].DeletionMark = false

		case e.OpLabels.OrchestrationIdentity[k] != nil:
			e.OpLabels.OrchestrationIdentity[k].DeletionMark = false

		default:
			tmp := v.DeepCopy()
			e.getLogger().WithField(logfields.Labels, logfields.Repr(tmp)).Debug("Assigning orchestration identity label")
			e.OpLabels.OrchestrationIdentity[k] = tmp
			changed = true
		}
	}

	if e.OpLabels.OrchestrationIdentity.DeleteMarked() || e.OpLabels.Disabled.DeleteMarked() {
		changed = true
	}
	e.Mutex.Unlock()

	return changed
}

// LeaveLocked removes the endpoint's directory from the system. Must be called
// with Endpoint's mutex locked.
func (e *Endpoint) LeaveLocked(owner Owner) {
	owner.RemoveFromEndpointQueue(uint64(e.ID))
	if c := e.Consumable; c != nil {
		c.Mutex.RLock()
		if e.L4Policy != nil {
			// Passing a new map of nil will purge all redirects
			e.cleanUnusedRedirects(owner, e.L4Policy.Ingress, nil)
			e.cleanUnusedRedirects(owner, e.L4Policy.Egress, nil)
		}
		c.Mutex.RUnlock()
	}

	if e.PolicyMap != nil {
		if err := e.PolicyMap.Close(); err != nil {
			e.getLogger().WithError(err).WithField(logfields.Path, e.PolicyMapPathLocked()).Warn("Unable to close policy map")
		}
	}

	e.L3Maps.Close()

	e.removeDirectory()

	e.SetStateLocked(StateDisconnected, "Endpoint removed")
}

func (e *Endpoint) removeDirectory() {
	os.RemoveAll(e.directoryPath())
}

func (e *Endpoint) RemoveDirectory() {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	e.removeDirectory()
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

// RegenerateWait should only be called when endpoint's state has successfully
// been changed to "waiting-to-regenerate"
func (e *Endpoint) RegenerateWait(owner Owner, reason string) error {
	if !<-e.Regenerate(owner, reason) {
		return fmt.Errorf("error while regenerating endpoint."+
			" For more info run: 'cilium endpoint get %d'", e.ID)
	}
	return nil
}

// SetContainerName modifies the endpoint's container name
func (e *Endpoint) SetContainerName(name string) {
	e.Mutex.Lock()
	e.ContainerName = name
	e.Mutex.Unlock()
}

// SetPodName modifies the endpoint's pod name
func (e *Endpoint) SetPodName(name string) {
	e.Mutex.Lock()
	e.PodName = name
	e.Mutex.Unlock()
}

// SetContainerID modifies the endpoint's container ID
func (e *Endpoint) SetContainerID(id string) {
	e.Mutex.Lock()
	e.DockerID = id
	e.Mutex.Unlock()
}

// GetContainerID returns the endpoint's container ID
func (e *Endpoint) GetContainerID() string {
	e.Mutex.RLock()
	id := e.DockerID
	e.Mutex.RUnlock()
	return id
}

// GetShortContainerID returns the endpoint's shortened container ID
func (e *Endpoint) GetShortContainerID() string {
	return e.GetContainerID()[:10]
}

// SetDockerEndpointID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerEndpointID(id string) {
	e.Mutex.Lock()
	e.DockerEndpointID = id
	e.Mutex.Unlock()
}

// SetDockerNetworkID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerNetworkID(id string) {
	e.Mutex.Lock()
	e.DockerNetworkID = id
	e.Mutex.Unlock()
}

// GetDockerNetworkID returns the endpoint's Docker Endpoint ID
func (e *Endpoint) GetDockerNetworkID() string {
	e.Mutex.RLock()
	id := e.DockerNetworkID
	e.Mutex.RUnlock()

	return id
}

// GetState returns the endpoint's state
// endpoint.Mutex may only be RLock()ed
func (e *Endpoint) GetStateLocked() string {
	return e.state
}

// GetState returns the endpoint's state
// endpoint.Mutex may only be RLock()ed
func (e *Endpoint) GetState() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	return e.GetStateLocked()
}

// SetStateLocked modifies the endpoint's state
// endpoint.Mutex must be held
// Returns true only if endpoints state was changed as requested
func (e *Endpoint) SetStateLocked(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state
	switch fromState { // From state
	case StateCreating:
		switch toState {
		case StateDisconnecting, StateWaitingForIdentity:
			goto OKState
		}
	case StateWaitingForIdentity:
		switch toState {
		case StateReady, StateDisconnecting:
			goto OKState
		}
	case StateReady:
		switch toState {
		case StateDisconnecting, StateWaitingToRegenerate:
			goto OKState
		}
	case StateDisconnecting:
		switch toState {
		case StateDisconnected:
			goto OKState
		}
	case StateDisconnected:
		// No valid transitions, as disconnected is a terminal state for the endpoint.
	case StateWaitingToRegenerate:
		switch toState {
		// Note that transitions to waiting-to-regenerate state
		case StateDisconnecting:
			goto OKState
		}
	case StateRegenerating:
		switch toState {
		// Even while the endpoint is regenerating it is
		// possible that further changes require a new
		// build. In this case the endpoint is transitioned
		// from the regenerating state to
		// waiting-to-regenerate state.
		case StateDisconnecting, StateWaitingToRegenerate:
			goto OKState
		}
	case StateRestoring:
		switch toState {
		case StateDisconnecting, StateRestoring, StateWaitingToRegenerate:
			goto OKState
		}
	}
	if toState != fromState {
		_, fileName, fileLine, _ := runtime.Caller(1)
		e.getLogger().WithFields(logrus.Fields{
			logfields.EndpointState + ".from": fromState,
			logfields.EndpointState + ".to":   toState,
			"file": fileName,
			"line": fileLine,
		}).Info("Invalid state transition skipped")
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)
	return true
}

// BuilderSetStateLocked modifies the endpoint's state
// endpoint.Mutex must be held
// endpoint BuildMutex must be held!
func (e *Endpoint) BuilderSetStateLocked(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state
	switch fromState { // From state
	case StateCreating, StateWaitingForIdentity, StateReady, StateDisconnecting, StateDisconnected:
		// No valid transitions for the builder
	case StateWaitingToRegenerate:
		switch toState {
		// Builder transitions the endpoint from
		// waiting-to-regenerate state to regenerating state
		// right after aquiring the endpoint lock, and while
		// endpoint's build mutex is held. All changes to
		// cilium and endpoint configuration, policy as well
		// as the existing set of security identities will be
		// reconsidered after this point, i.e., even if some
		// of them are changed regeneration need not be queued
		// if the endpoint is already in waiting-to-regenerate
		// state.
		case StateRegenerating:
			goto OKState
		}
	case StateRegenerating:
		switch toState {
		// While still holding the build mutex, the builder
		// tries to transition the endpoint to ready
		// state. But since the endpoint mutex was released
		// for the duration of the bpf generation, it is
		// possible that another build request has been
		// queued. In this case the endpoint has been
		// transitioned to waiting-to-regenerate state
		// already, and the transition to ready state is
		// skipped.
		case StateReady:
			goto OKState
		}
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)
	return true
}

// bumpPolicyRevision marks the endpoint to be running the next scheduled
// policy revision as setup by e.regenerate(). endpoint.Mutex should not be held.
func (e *Endpoint) bumpPolicyRevision(revision uint64) {
	e.Mutex.Lock()
	if revision > e.policyRevision {
		e.policyRevision = revision
		e.updateLogger()
	}
	e.Mutex.Unlock()
}
