// Copyright 2016-2019 Authors of Cilium
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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/notifications"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/sirupsen/logrus"

	"golang.org/x/sys/unix"
)

const (
	maxLogs = 256
)

var (
	EndpointMutableOptionLibrary = option.GetEndpointMutableOptionLibrary()
)

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

	// IpvlanMapName specifies the tail call map for EP on egress used with ipvlan.
	IpvlanMapName = "cilium_lxc_ipve_"
)

// compile time interface check
var _ notifications.RegenNotificationInfo = &Endpoint{}

// Endpoint represents a container or similar which can be individually
// addresses on L3 with its own IP addresses. This structured is managed by the
// endpoint manager in pkg/endpointmanager.
//
// The representation of the Endpoint which is serialized to disk for restore
// purposes is the serializableEndpoint type in this package.
type Endpoint struct {
	owner regeneration.Owner

	// ID of the endpoint, unique in the scope of the node
	ID uint16

	// mutex protects write operations to this endpoint structure except
	// for the logger field which has its own mutex
	mutex lock.RWMutex

	// containerName is the name given to the endpoint by the container runtime
	containerName string

	// containerID is the container ID that docker has assigned to the endpoint
	containerID string

	// dockerNetworkID is the network ID of the libnetwork network if the
	// endpoint is a docker managed container which uses libnetwork
	dockerNetworkID string

	// dockerEndpointID is the Docker network endpoint ID if managed by
	// libnetwork
	dockerEndpointID string

	// Corresponding BPF map identifier for tail call map of ipvlan datapath
	datapathMapID int

	// isDatapathMapPinned denotes whether the datapath map has been pinned.
	isDatapathMapPinned bool

	// ifName is the name of the host facing interface (veth pair) which
	// connects into the endpoint
	ifName string

	// ifIndex is the interface index of the host face interface (veth pair)
	ifIndex int

	// OpLabels is the endpoint's label configuration
	//
	// FIXME: Rename this field to Labels
	OpLabels pkgLabels.OpLabels

	// identityRevision is incremented each time the identity label
	// information of the endpoint has changed
	identityRevision int

	// mac is the MAC address of the endpoint
	//
	mac mac.MAC // Container MAC address.

	// IPv6 is the IPv6 address of the endpoint
	IPv6 addressing.CiliumIPv6

	// IPv4 is the IPv4 address of the endpoint
	IPv4 addressing.CiliumIPv4

	// nodeMAC is the MAC of the node (agent). The MAC is different for every endpoint.
	nodeMAC mac.MAC

	// SecurityIdentity is the security identity of this endpoint. This is computed from
	// the endpoint's labels.
	SecurityIdentity *identity.Identity `json:"SecLabel"`

	// hasSidecarProxy indicates whether the endpoint has been injected by
	// Istio with a Cilium-compatible sidecar proxy. If true, the sidecar proxy
	// will be used to apply L7 policy rules. Otherwise, Cilium's node-wide
	// proxy will be used.
	// TODO: Currently this applies only to HTTP L7 rules. Kafka L7 rules are still enforced by Cilium's node-wide Kafka proxy.
	hasSidecarProxy bool

	// policyMap is the policy related state of the datapath including
	// reference to all policy related BPF
	policyMap *policymap.PolicyMap

	// Options determine the datapath configuration of the endpoint.
	Options *option.IntOptions

	// status contains the last n state transitions this endpoint went through
	status *EndpointStatus

	// DNSHistory is the collection of still-valid DNS responses intercepted for
	// this endpoint.
	DNSHistory *fqdn.DNSCache

	// DNSZombies is the collection of DNS IPs that have expired in or been
	// evicted from DNSHistory. They are held back from deletion until we can
	// confirm that no existing connection is using them.
	DNSZombies *fqdn.DNSZombieMappings

	// dnsHistoryTrigger is the trigger to write down the lxc_config.h to make
	// sure that restores when DNS policy is in there are correct
	dnsHistoryTrigger *trigger.Trigger

	// state is the state the endpoint is in. See setState()
	state string

	// bpfHeaderfileHash is the hash of the last BPF headerfile that has been
	// compiled and installed.
	bpfHeaderfileHash string

	// K8sPodName is the Kubernetes pod name of the endpoint
	K8sPodName string

	// K8sNamespace is the Kubernetes namespace of the endpoint
	K8sNamespace string

	// policyRevision is the policy revision this endpoint is currently on
	// to modify this field please use endpoint.setPolicyRevision instead
	policyRevision uint64

	// policyRevisionSignals contains a map of PolicyRevision signals that
	// should be triggered once the policyRevision reaches the wanted wantedRev.
	policyRevisionSignals map[*policySignal]bool

	// proxyPolicyRevision is the policy revision that has been applied to
	// the proxy.
	proxyPolicyRevision uint64

	// proxyStatisticsMutex is the mutex that must be held to read or write
	// proxyStatistics.
	proxyStatisticsMutex lock.RWMutex

	proxy EndpointProxy

	// proxyStatistics contains statistics of proxy redirects.
	// They keys in this map are policy.ProxyIDs.
	// You must hold Endpoint.proxyStatisticsMutex to read or write it.
	proxyStatistics map[string]*models.ProxyStatistics

	// nextPolicyRevision is the policy revision that the endpoint has
	// updated to and that will become effective with the next regenerate
	nextPolicyRevision uint64

	// forcePolicyCompute full endpoint policy recomputation
	// Set when endpoint options have been changed. Cleared right before releasing the
	// endpoint mutex after policy recalculation.
	forcePolicyCompute bool

	// buildMutex synchronizes builds of individual endpoints and locks out
	// deletion during builds
	buildMutex lock.Mutex

	// logger is a logrus object with fields set to report an endpoints information.
	// You must hold Endpoint.Mutex to read or write it (but not to log with it).
	logger unsafe.Pointer

	// controllers is the list of async controllers syncing the endpoint to
	// other resources
	controllers *controller.Manager

	// realizedRedirects maps the ID of each proxy redirect that has been
	// successfully added into a proxy for this endpoint, to the redirect's
	// proxy port number.
	// You must hold Endpoint.Mutex to read or write it.
	realizedRedirects map[string]uint16

	// ctCleaned indicates whether the conntrack table has already been
	// cleaned when this endpoint was first created
	ctCleaned bool

	hasBPFProgram chan struct{}

	// selectorPolicy represents a reference to the shared SelectorPolicy
	// for all endpoints that have the same Identity.
	selectorPolicy policy.SelectorPolicy

	desiredPolicy *policy.EndpointPolicy

	realizedPolicy *policy.EndpointPolicy

	visibilityPolicy *policy.VisibilityPolicy

	eventQueue *eventqueue.EventQueue

	// DatapathConfiguration is the endpoint's datapath configuration as
	// passed in via the plugin that created the endpoint, e.g. the CNI
	// plugin which performed the plumbing will enable certain datapath
	// features according to the mode selected.
	DatapathConfiguration models.EndpointDatapathConfiguration

	aliveCtx        context.Context
	aliveCancel     context.CancelFunc
	regenFailedChan chan struct{}
	// exposed is a channel that is closed when the endpoint is exposed in the
	// endpoint manager.
	exposed chan struct{}

	allocator cache.IdentityAllocator
}

// SetAllocator sets the identity allocator for this endpoint.
func (e *Endpoint) SetAllocator(allocator cache.IdentityAllocator) {
	e.unconditionalLock()
	defer e.unlock()
	e.allocator = allocator
}

// UpdateController updates the controller with the specified name with the
// provided list of parameters in endpoint's list of controllers.
func (e *Endpoint) UpdateController(name string, params controller.ControllerParams) {
	params.Context = e.aliveCtx
	e.controllers.UpdateController(name, params)
}

// GetIfIndex returns the ifIndex for this endpoint.
func (e *Endpoint) GetIfIndex() int {
	return e.ifIndex
}

// LXCMac returns the LXCMac for this endpoint.
func (e *Endpoint) LXCMac() mac.MAC {
	return e.mac
}

// closeBPFProgramChannel closes the channel that signals whether the endpoint
// has had its BPF program compiled. If the channel is already closed, this is
// a no-op.
func (e *Endpoint) closeBPFProgramChannel() {
	select {
	case <-e.hasBPFProgram:
	default:
		close(e.hasBPFProgram)
	}
}

// bpfProgramInstalled returns whether a BPF program has been generated for this
// endpoint.
func (e *Endpoint) bpfProgramInstalled() bool {
	select {
	case <-e.hasBPFProgram:
		return true
	default:
		return false
	}
}

// HasIpvlanDataPath returns whether the daemon is running in ipvlan mode.
func (e *Endpoint) HasIpvlanDataPath() bool {
	if e.datapathMapID > 0 {
		return true
	}
	return false
}

// GetIngressPolicyEnabledLocked returns whether ingress policy enforcement is
// enabled for endpoint or not. The endpoint's mutex must be held.
func (e *Endpoint) GetIngressPolicyEnabledLocked() bool {
	return e.desiredPolicy.IngressPolicyEnabled
}

// GetEgressPolicyEnabledLocked returns whether egress policy enforcement is
// enabled for endpoint or not. The endpoint's mutex must be held.
func (e *Endpoint) GetEgressPolicyEnabledLocked() bool {
	return e.desiredPolicy.EgressPolicyEnabled
}

// waitForProxyCompletions blocks until all proxy changes have been completed.
// Called with buildMutex held.
func (e *Endpoint) waitForProxyCompletions(proxyWaitGroup *completion.WaitGroup) error {
	if proxyWaitGroup == nil {
		return nil
	}

	err := proxyWaitGroup.Context().Err()
	if err != nil {
		return fmt.Errorf("context cancelled before waiting for proxy updates: %s", err)
	}

	start := time.Now()

	e.getLogger().Debug("Waiting for proxy updates to complete...")
	err = proxyWaitGroup.Wait()
	if err != nil {
		return fmt.Errorf("proxy state changes failed: %s", err)
	}
	e.getLogger().Debug("Wait time for proxy updates: ", time.Since(start))

	return nil
}

// NewEndpointWithState creates a new endpoint useful for testing purposes
func NewEndpointWithState(owner regeneration.Owner, proxy EndpointProxy, allocator cache.IdentityAllocator, ID uint16, state string) *Endpoint {
	ep := &Endpoint{
		owner:           owner,
		proxy:           proxy,
		ID:              ID,
		OpLabels:        pkgLabels.NewOpLabels(),
		status:          NewEndpointStatus(),
		DNSHistory:      fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		DNSZombies:      fqdn.NewDNSZombieMappings(option.Config.ToFQDNsMaxDeferredConnectionDeletes),
		state:           state,
		hasBPFProgram:   make(chan struct{}, 0),
		controllers:     controller.NewManager(),
		eventQueue:      eventqueue.NewEventQueueBuffered(fmt.Sprintf("endpoint-%d", ID), option.Config.EndpointQueueSize),
		desiredPolicy:   policy.NewEndpointPolicy(owner.GetPolicyRepository()),
		regenFailedChan: make(chan struct{}, 1),
		allocator:       allocator,
		exposed:         make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	ep.aliveCancel = cancel
	ep.aliveCtx = ctx
	ep.realizedPolicy = ep.desiredPolicy

	ep.SetDefaultOpts(option.Config.Opts)
	ep.UpdateLogger(nil)

	ep.eventQueue.Run()

	return ep
}

// GetID returns the endpoint's ID as a 64-bit unsigned integer.
func (e *Endpoint) GetID() uint64 {
	return uint64(e.ID)
}

// GetLabels returns the labels as slice
func (e *Endpoint) GetLabels() []string {
	if e.SecurityIdentity == nil {
		return []string{}
	}

	return e.SecurityIdentity.Labels.GetModel()
}

// GetSecurityIdentity returns the security identity of the endpoint. It assumes
// the endpoint's mutex is held.
func (e *Endpoint) GetSecurityIdentity() (*identity.Identity, error) {
	if err := e.rlockAlive(); err != nil {
		return nil, err
	}
	defer e.runlock()
	return e.SecurityIdentity, nil
}

// GetID16 returns the endpoint's ID as a 16-bit unsigned integer.
func (e *Endpoint) GetID16() uint16 {
	return e.ID
}

// getK8sPodLabels returns all labels that exist in the endpoint and were
// derived from k8s pod.
func (e *Endpoint) getK8sPodLabels() pkgLabels.Labels {
	e.unconditionalRLock()
	defer e.runlock()
	allLabels := e.OpLabels.AllLabels()
	if allLabels == nil {
		return nil
	}

	allLabelsFromK8s := allLabels.GetFromSource(pkgLabels.LabelSourceK8s)

	k8sEPPodLabels := pkgLabels.Labels{}
	for k, v := range allLabelsFromK8s {
		if !strings.HasPrefix(v.Key, ciliumio.PodNamespaceMetaLabels) &&
			!strings.HasPrefix(v.Key, ciliumio.PolicyLabelServiceAccount) &&
			!strings.HasPrefix(v.Key, ciliumio.PodNamespaceLabel) {
			k8sEPPodLabels[k] = v
		}
	}
	return k8sEPPodLabels
}

// GetLabelsSHA returns the SHA of labels
func (e *Endpoint) GetLabelsSHA() string {
	if e.SecurityIdentity == nil {
		return ""
	}

	return e.SecurityIdentity.GetLabelsSHA256()
}

// GetOpLabels returns the labels as slice
func (e *Endpoint) GetOpLabels() []string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.OpLabels.IdentityLabels().GetModel()
}

// GetOptions returns the datapath configuration options of the endpoint.
func (e *Endpoint) GetOptions() *option.IntOptions {
	return e.Options
}

// GetIPv4Address returns the IPv4 address of the endpoint as a string
func (e *Endpoint) GetIPv4Address() string {
	return e.IPv4.String()
}

// GetIPv6Address returns the IPv6 address of the endpoint as a string
func (e *Endpoint) GetIPv6Address() string {
	return e.IPv6.String()
}

// IPv4Address returns the IPv4 address of the endpoint
func (e *Endpoint) IPv4Address() addressing.CiliumIPv4 {
	return e.IPv4
}

// IPv6Address returns the IPv6 address of the endpoint
func (e *Endpoint) IPv6Address() addressing.CiliumIPv6 {
	return e.IPv6
}

// GetNodeMAC returns the MAC address of the node from this endpoint's perspective.
func (e *Endpoint) GetNodeMAC() mac.MAC {
	return e.nodeMAC
}

func (e *Endpoint) HasSidecarProxy() bool {
	return e.hasSidecarProxy
}

// ConntrackName returns the name suffix for the endpoint-specific bpf
// conntrack map, which is a 5-digit endpoint ID, or "global" when the
// global map should be used.
func (e *Endpoint) ConntrackName() string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.conntrackName()
}

// ConntrackNameLocked returns the name suffix for the endpoint-specific bpf
// conntrack map, which is a 5-digit endpoint ID, or "global" when the
// global map should be used.
// Must be called with the endpoint locked.
func (e *Endpoint) ConntrackNameLocked() string {
	return e.conntrackName()
}

// ConntrackName returns the name suffix for the endpoint-specific bpf
// conntrack map, which is a 5-digit endpoint ID, or "global" when the
// global map should be used.
// Must be called with the endpoint locked.
func (e *Endpoint) conntrackName() string {
	if e.ConntrackLocalLocked() {
		return fmt.Sprintf("%05d", int(e.ID))
	}
	return "global"
}

// StringID returns the endpoint's ID in a string.
func (e *Endpoint) StringID() string {
	return strconv.Itoa(int(e.ID))
}

func (e *Endpoint) GetIdentity() identity.NumericIdentity {
	if e.SecurityIdentity != nil {
		return e.SecurityIdentity.ID
	}

	return identity.InvalidIdentity
}

// Allows is only used for unit testing
func (e *Endpoint) Allows(id identity.NumericIdentity) bool {
	e.unconditionalRLock()
	defer e.runlock()

	keyToLookup := policy.Key{
		Identity:         uint32(id),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}

	_, ok := e.desiredPolicy.PolicyMapState[keyToLookup]
	return ok
}

// String returns endpoint on a JSON format.
func (e *Endpoint) String() string {
	e.unconditionalRLock()
	defer e.runlock()
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// optionChanged is a callback used with pkg/option to apply the options to an
// endpoint.  Not used for anything at the moment.
func optionChanged(key string, value option.OptionSetting, data interface{}) {
}

// applyOptsLocked applies the given options to the endpoint's options and
// returns true if there were any options changed.
func (e *Endpoint) applyOptsLocked(opts option.OptionMap) bool {
	changed := e.Options.ApplyValidated(opts, optionChanged, e) > 0
	_, exists := opts[option.Debug]
	if exists && changed {
		e.UpdateLogger(nil)
	}
	return changed
}

// forcePolicyComputation ensures that upon the next policy calculation for this
// Endpoint, that no short-circuiting of said operation occurs.
func (e *Endpoint) forcePolicyComputation() {
	e.forcePolicyCompute = true
}

// SetDefaultOpts initializes the endpoint Options and configures the specified
// options.
func (e *Endpoint) SetDefaultOpts(opts *option.IntOptions) {
	if e.Options == nil {
		e.Options = option.NewIntOptions(&EndpointMutableOptionLibrary)
	}
	if e.Options.Library == nil {
		e.Options.Library = &EndpointMutableOptionLibrary
	}
	if e.Options.Opts == nil {
		e.Options.Opts = option.OptionMap{}
	}

	if opts != nil {
		epOptLib := option.GetEndpointMutableOptionLibrary()
		for k := range epOptLib {
			e.Options.SetValidated(k, opts.GetValue(k))
		}
	}
	e.UpdateLogger(nil)
}

// ConntrackLocal determines whether this endpoint is currently using a local
// table to handle connection tracking (true), or the global table (false).
func (e *Endpoint) ConntrackLocal() bool {
	e.unconditionalRLock()
	defer e.runlock()

	return e.ConntrackLocalLocked()
}

// ConntrackLocalLocked is the same as ConntrackLocal, but assumes that the
// endpoint is already locked for reading.
func (e *Endpoint) ConntrackLocalLocked() bool {
	if e.SecurityIdentity == nil || e.Options == nil ||
		!e.Options.IsEnabled(option.ConntrackLocal) {
		return false
	}

	return true
}

// base64 returns the endpoint in a base64 format.
func (e *Endpoint) base64() (string, error) {
	var (
		jsonBytes []byte
		err       error
	)

	jsonBytes, err = json.Marshal(e)
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

	if err := json.Unmarshal(jsonBytes, ep); err != nil {
		return fmt.Errorf("error unmarshaling serializableEndpoint from base64 representation: %s", err)
	}

	return nil
}

// FilterEPDir returns a list of directories' names that possible belong to an endpoint.
func FilterEPDir(dirFiles []os.FileInfo) []string {
	eptsID := []string{}
	for _, file := range dirFiles {
		if file.IsDir() {
			_, err := strconv.ParseUint(file.Name(), 10, 16)
			if err == nil || strings.HasSuffix(file.Name(), nextDirectorySuffix) || strings.HasSuffix(file.Name(), nextFailedDirectorySuffix) {
				eptsID = append(eptsID, file.Name())
			}
		}
	}
	return eptsID
}

// parseEndpoint parses the given strEp which is in the form of:
// common.CiliumCHeaderPrefix + common.Version + ":" + endpointBase64
// Note that the parse'd endpoint's identity is only partially restored. The
// caller must call `SetIdentity()` to make the returned endpoint's identity useful.
func parseEndpoint(ctx context.Context, owner regeneration.Owner, strEp string) (*Endpoint, error) {
	// TODO: Provide a better mechanism to update from old version once we bump
	// TODO: cilium version.
	strEpSlice := strings.Split(strEp, ":")
	if len(strEpSlice) != 2 {
		return nil, fmt.Errorf("invalid format %q. Should contain a single ':'", strEp)
	}
	ep := Endpoint{
		owner: owner,
	}

	if err := parseBase64ToEndpoint(strEpSlice[1], &ep); err != nil {
		return nil, fmt.Errorf("failed to parse restored endpoint: %s", err)
	}

	// Validate the options that were parsed
	ep.SetDefaultOpts(ep.Options)

	// Initialize fields to values which are non-nil that are not serialized.
	ep.hasBPFProgram = make(chan struct{}, 0)
	ep.desiredPolicy = policy.NewEndpointPolicy(owner.GetPolicyRepository())
	ep.realizedPolicy = ep.desiredPolicy
	ep.controllers = controller.NewManager()
	ep.regenFailedChan = make(chan struct{}, 1)
	ep.exposed = make(chan struct{})

	ctx, cancel := context.WithCancel(ctx)
	ep.aliveCancel = cancel
	ep.aliveCtx = ctx

	// We need to check for nil in Status, CurrentStatuses and Log, since in
	// some use cases, status will be not nil and Cilium will eventually
	// error/panic if CurrentStatus or Log are not initialized correctly.
	// Reference issue GH-2477
	if ep.status == nil || ep.status.CurrentStatuses == nil || ep.status.Log == nil {
		ep.status = NewEndpointStatus()
	}

	// Make sure the endpoint has an identity, using the 'init' identity if none.
	if ep.SecurityIdentity == nil {
		ep.SecurityIdentity = identity.LookupReservedIdentity(identity.ReservedIdentityInit)
	}
	ep.SecurityIdentity.Sanitize()

	ep.UpdateLogger(nil)

	ep.setState(StateRestoring, "Endpoint restoring")

	return &ep, nil
}

func (e *Endpoint) LogStatus(typ StatusType, code StatusCode, msg string) {
	e.unconditionalLock()
	defer e.unlock()
	// FIXME GH2323 instead of a mutex we could use a channel to send the status
	// log message to a single writer?
	e.logStatusLocked(typ, code, msg)
}

func (e *Endpoint) LogStatusOK(typ StatusType, msg string) {
	e.LogStatus(typ, OK, msg)
}

// LogStatusOKLocked will log an OK message of the given status type with the
// given msg string.
// must be called with endpoint.Mutex held
func (e *Endpoint) LogStatusOKLocked(typ StatusType, msg string) {
	e.logStatusLocked(typ, OK, msg)
}

// logStatusLocked logs a status message
// must be called with endpoint.Mutex held
func (e *Endpoint) logStatusLocked(typ StatusType, code StatusCode, msg string) {
	e.status.indexMU.Lock()
	defer e.status.indexMU.Unlock()
	sts := &statusLogMsg{
		Status: Status{
			Code:  code,
			Msg:   msg,
			Type:  typ,
			State: e.state,
		},
		Timestamp: time.Now().UTC(),
	}
	e.status.addStatusLog(sts)
	e.getLogger().WithFields(logrus.Fields{
		"code":                   sts.Status.Code,
		"type":                   sts.Status.Type,
		logfields.EndpointState:  sts.Status.State,
		logfields.PolicyRevision: e.policyRevision,
	}).Debug(msg)
}

type UpdateValidationError struct {
	msg string
}

func (e UpdateValidationError) Error() string { return e.msg }

type UpdateCompilationError struct {
	msg string
}

func (e UpdateCompilationError) Error() string { return e.msg }

// UpdateStateChangeError is an error that indicates that updating the state
// of an endpoint was unsuccessful.
// Implements error interface.
type UpdateStateChangeError struct {
	msg string
}

func (e UpdateStateChangeError) Error() string { return e.msg }

// Update modifies the endpoint options and *always* tries to regenerate the
// endpoint's program. Returns an error if the provided options are not valid,
// if there was an issue triggering policy updates for the given endpoint,
// or if endpoint regeneration was unable to be triggered. Note that the
// LabelConfiguration in the EndpointConfigurationSpec is *not* consumed here.
func (e *Endpoint) Update(cfg *models.EndpointConfigurationSpec) error {
	om, err := EndpointMutableOptionLibrary.ValidateConfigurationMap(cfg.Options)
	if err != nil {
		return UpdateValidationError{err.Error()}
	}

	if err := e.lockAlive(); err != nil {
		return err
	}

	e.getLogger().WithField("configuration-options", cfg).Debug("updating endpoint configuration options")

	// CurrentStatus will be not OK when we have an uncleared error in BPF,
	// policy or Other. We should keep trying to regenerate in the hopes of
	// succeeding.
	// Note: This "retry" behaviour is better suited to a controller, and can be
	// moved there once we have an endpoint regeneration controller.
	regenCtx := &regeneration.ExternalRegenerationMetadata{
		Reason: "endpoint was updated via API",
	}

	// If configuration options are provided, we only regenerate if necessary.
	// Otherwise always regenerate.
	if cfg.Options == nil {
		regenCtx.RegenerationLevel = regeneration.RegenerateWithDatapathRebuild
		regenCtx.Reason = "endpoint was manually regenerated via API"
	} else if e.updateAndOverrideEndpointOptions(om) || e.status.CurrentStatus() != OK {
		regenCtx.RegenerationLevel = regeneration.RegenerateWithDatapathRewrite
	}

	if regenCtx.RegenerationLevel > regeneration.RegenerateWithoutDatapath {
		e.getLogger().Debug("need to regenerate endpoint; checking state before" +
			" attempting to regenerate")

		// TODO / FIXME: GH-3281: need ways to queue up regenerations per-endpoint.

		// Default timeout for PATCH /endpoint/{id}/config is 60 seconds, so put
		// timeout in this function a bit below that timeout. If the timeout
		// for clients in API is below this value, they will get a message containing
		// "context deadline exceeded".
		timeout := time.After(EndpointGenerationTimeout)

		// Check for endpoint state every second.
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		e.unlock()
		for {
			select {
			case <-ticker.C:
				if err := e.lockAlive(); err != nil {
					return err
				}
				// Check endpoint state before attempting configuration update because
				// configuration updates can only be applied when the endpoint is in
				// specific states. See GH-3058.
				stateTransitionSucceeded := e.setState(StateWaitingToRegenerate, regenCtx.Reason)
				if stateTransitionSucceeded {
					e.unlock()
					e.Regenerate(regenCtx)
					return nil
				}
				e.unlock()
			case <-timeout:
				e.getLogger().Warning("timed out waiting for endpoint state to change")
				return UpdateStateChangeError{fmt.Sprintf("unable to regenerate endpoint program because state transition to %s was unsuccessful; check `cilium endpoint log %d` for more information", StateWaitingToRegenerate, e.ID)}
			}
		}

	}

	e.unlock()
	return nil
}

// HasLabels returns whether endpoint e contains all labels l. Will return 'false'
// if any label in l is not in the endpoint's labels.
func (e *Endpoint) HasLabels(l pkgLabels.Labels) bool {
	e.unconditionalRLock()
	defer e.runlock()

	return e.hasLabelsRLocked(l)
}

// hasLabelsRLocked returns whether endpoint e contains all labels l. Will
// return 'false' if any label in l is not in the endpoint's labels.
// e.Mutex must be RLocked
func (e *Endpoint) hasLabelsRLocked(l pkgLabels.Labels) bool {
	allEpLabels := e.OpLabels.AllLabels()

	for _, v := range l {
		found := false
		for _, j := range allEpLabels {
			if j.Equals(&v) {
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

// replaceInformationLabels replaces the information labels of the endpoint.
// Passing a nil set of labels will not perform any action.
// Must be called with e.Mutex.Lock().
func (e *Endpoint) replaceInformationLabels(l pkgLabels.Labels) {
	if l == nil {
		return
	}
	e.OpLabels.ReplaceInformationLabels(l, e.getLogger())
}

// replaceIdentityLabels replaces the identity labels of the endpoint. If a net
// changed occurred, the identityRevision is bumped and returned, otherwise 0 is
// returned.
// Passing a nil set of labels will not perform any action and will return the
// current endpoint's identityRevision.
// Must be called with e.Mutex.Lock().
func (e *Endpoint) replaceIdentityLabels(l pkgLabels.Labels) int {
	if l == nil {
		return e.identityRevision
	}

	changed := e.OpLabels.ReplaceIdentityLabels(l, e.getLogger())
	rev := 0
	if changed {
		e.identityRevision++
		rev = e.identityRevision
	}

	return rev
}

// DeleteConfig is the endpoint deletion configuration
type DeleteConfig struct {
	NoIPRelease       bool
	NoIdentityRelease bool
}

// leaveLocked removes the endpoint's directory from the system. Must be called
// with Endpoint's mutex AND buildMutex locked.
//
// Note: leaveLocked() is called indirectly from endpoint restore logic for
// endpoints which failed to be restored. Any cleanup routine of leaveLocked()
// which depends on kvstore connectivity must be protected by a flag in
// DeleteConfig and the restore logic must opt-out of it.
func (e *Endpoint) leaveLocked(proxyWaitGroup *completion.WaitGroup, conf DeleteConfig) []error {
	errors := []error{}

	if !option.Config.DryMode {
		e.owner.Datapath().Loader().Unload(e.createEpInfoCache(""))
	}

	if e.SecurityIdentity != nil && len(e.realizedRedirects) > 0 {
		// Passing a new map of nil will purge all redirects
		finalize, _ := e.removeOldRedirects(nil, proxyWaitGroup)
		if finalize != nil {
			finalize()
		}
	}

	if e.policyMap != nil {
		if err := e.policyMap.Close(); err != nil {
			errors = append(errors, fmt.Errorf("unable to close policymap %s: %s", e.policyMap.String(), err))
		}
	}

	if !conf.NoIdentityRelease && e.SecurityIdentity != nil {
		identitymanager.Remove(e.SecurityIdentity)

		releaseCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
		defer cancel()

		_, err := e.allocator.Release(releaseCtx, e.SecurityIdentity)
		if err != nil {
			errors = append(errors, fmt.Errorf("unable to release identity: %s", err))
		}
		e.removeNetworkPolicy()
		e.SecurityIdentity = nil
	}

	e.removeDirectories()
	e.controllers.RemoveAll()
	e.cleanPolicySignals()

	if e.dnsHistoryTrigger != nil {
		e.dnsHistoryTrigger.Shutdown()
	}

	if e.ConntrackLocalLocked() {
		ctmap.CloseLocalMaps(e.conntrackName())
	} else if !option.Config.DryMode {
		e.scrubIPsInConntrackTableLocked()
	}

	e.setState(StateDisconnected, "Endpoint removed")

	endpointPolicyStatus.Remove(e.ID)
	e.getLogger().Info("Removed endpoint")

	return errors
}

// RegenerateWait should only be called when endpoint's state has successfully
// been changed to "waiting-to-regenerate"
func (e *Endpoint) RegenerateWait(reason string) error {
	if !<-e.Regenerate(&regeneration.ExternalRegenerationMetadata{Reason: reason}) {
		return fmt.Errorf("error while regenerating endpoint."+
			" For more info run: 'cilium endpoint get %d'", e.ID)
	}
	return nil
}

// GetContainerName returns the name of the container for the endpoint.
func (e *Endpoint) GetContainerName() string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.containerName
}

// SetContainerName modifies the endpoint's container name
func (e *Endpoint) SetContainerName(name string) {
	e.unconditionalLock()
	e.containerName = name
	e.unlock()
}

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	e.unconditionalRLock()
	ns := e.K8sNamespace
	e.runlock()
	return ns
}

// SetK8sNamespace modifies the endpoint's pod name
func (e *Endpoint) SetK8sNamespace(name string) {
	e.unconditionalLock()
	e.K8sNamespace = name
	e.UpdateLogger(map[string]interface{}{
		logfields.K8sPodName: e.getK8sNamespaceAndPodName(),
	})
	e.unlock()
}

// K8sNamespaceAndPodNameIsSet returns true if the pod name is set
func (e *Endpoint) K8sNamespaceAndPodNameIsSet() bool {
	e.unconditionalLock()
	podName := e.getK8sNamespaceAndPodName()
	e.unlock()
	return podName != "" && podName != "/"
}

// GetK8sPodName returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sPodName() string {
	e.unconditionalRLock()
	k8sPodName := e.K8sPodName
	e.runlock()

	return k8sPodName
}

// HumanStringLocked returns the endpoint's most human readable identifier as string
func (e *Endpoint) HumanStringLocked() string {
	if pod := e.getK8sNamespaceAndPodName(); pod != "" {
		return pod
	}

	return e.StringID()
}

// GetK8sNamespaceAndPodName returns the corresponding namespace and pod
// name for this endpoint.
func (e *Endpoint) GetK8sNamespaceAndPodName() string {
	e.unconditionalRLock()
	defer e.runlock()

	return e.getK8sNamespaceAndPodName()
}

func (e *Endpoint) getK8sNamespaceAndPodName() string {
	return e.K8sNamespace + "/" + e.K8sPodName
}

// SetK8sPodName modifies the endpoint's pod name
func (e *Endpoint) SetK8sPodName(name string) {
	e.unconditionalLock()
	e.K8sPodName = name
	e.UpdateLogger(map[string]interface{}{
		logfields.K8sPodName: e.getK8sNamespaceAndPodName(),
	})
	e.unlock()
}

// SetContainerID modifies the endpoint's container ID
func (e *Endpoint) SetContainerID(id string) {
	e.unconditionalLock()
	e.containerID = id
	e.UpdateLogger(map[string]interface{}{
		logfields.ContainerID: e.getShortContainerID(),
	})
	e.unlock()
}

// GetContainerID returns the endpoint's container ID
func (e *Endpoint) GetContainerID() string {
	e.unconditionalRLock()
	cID := e.containerID
	e.runlock()
	return cID
}

// GetShortContainerID returns the endpoint's shortened container ID
func (e *Endpoint) GetShortContainerID() string {
	e.unconditionalRLock()
	defer e.runlock()

	return e.getShortContainerID()
}

func (e *Endpoint) getShortContainerID() string {
	if e == nil {
		return ""
	}

	caplen := 10
	if len(e.containerID) <= caplen {
		return e.containerID
	}

	return e.containerID[:caplen]

}

// SetDockerEndpointID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerEndpointID(id string) {
	e.unconditionalLock()
	e.dockerEndpointID = id
	e.unlock()
}

func (e *Endpoint) GetDockerEndpointID() string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.dockerEndpointID
}

// SetDockerNetworkID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerNetworkID(id string) {
	e.unconditionalLock()
	e.dockerNetworkID = id
	e.unlock()
}

// GetDockerNetworkID returns the endpoint's Docker Endpoint ID
func (e *Endpoint) GetDockerNetworkID() string {
	e.unconditionalRLock()
	defer e.runlock()

	return e.dockerNetworkID
}

// setDatapathMapIDAndPinMap modifies the endpoint's datapath map ID
func (e *Endpoint) setDatapathMapIDAndPinMap(id int) error {
	e.datapathMapID = id
	return e.pinDatapathMap()
}

// getState returns the endpoint's state
// endpoint.Mutex may only be.rlockAlive()ed
func (e *Endpoint) getState() string {
	return e.state
}

// GetState returns the endpoint's state
// endpoint.Mutex may only be.rlockAlive()ed
func (e *Endpoint) GetState() string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.getState()
}

// SetState modifies the endpoint's state. Returns true only if endpoints state
// was changed as requested
func (e *Endpoint) SetState(toState, reason string) bool {
	e.unconditionalLock()
	defer e.unlock()

	return e.setState(toState, reason)
}

func (e *Endpoint) setState(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state

	switch fromState { // From state
	case "": // Special case for capturing initial state transitions like
		// nil --> StateWaitingForIdentity, StateRestoring
		switch toState {
		case StateWaitingForIdentity, StateRestoring:
			goto OKState
		}
	case StateCreating:
		switch toState {
		case StateDisconnecting, StateWaitingForIdentity, StateRestoring:
			goto OKState
		}
	case StateWaitingForIdentity:
		switch toState {
		case StateReady, StateDisconnecting:
			goto OKState
		}
	case StateReady:
		switch toState {
		case StateWaitingForIdentity, StateDisconnecting, StateWaitingToRegenerate, StateRestoring:
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
		// Note that transitions to StateWaitingToRegenerate are not allowed,
		// as callers of this function enqueue regenerations if 'true' is
		// returned. We don't want to return 'true' for the case of
		// transitioning to StateWaitingToRegenerate, as this means that a
		// regeneration is already queued up. Callers would then queue up
		// another unneeded regeneration, which is undesired.
		case StateWaitingForIdentity, StateDisconnecting, StateRestoring:
			goto OKState
		// Don't log this state transition being invalid below so that we don't
		// put warnings in the logs for a case which does not result in incorrect
		// behavior.
		case StateWaitingToRegenerate:
			return false
		}
	case StateRegenerating:
		switch toState {
		// Even while the endpoint is regenerating it is
		// possible that further changes require a new
		// build. In this case the endpoint is transitioned
		// from the regenerating state to
		// waiting-for-identity or waiting-to-regenerate state.
		case StateWaitingForIdentity, StateDisconnecting, StateWaitingToRegenerate, StateRestoring:
			goto OKState
		}
	case StateRestoring:
		switch toState {
		case StateDisconnecting, StateRestoring:
			goto OKState
		}
	}
	if toState != fromState {
		_, fileName, fileLine, _ := runtime.Caller(1)
		e.getLogger().WithFields(logrus.Fields{
			logfields.EndpointState + ".from": fromState,
			logfields.EndpointState + ".to":   toState,
			"file":                            fileName,
			"line":                            fileLine,
		}).Info("Invalid state transition skipped")
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)

	if fromState != "" {
		metrics.EndpointStateCount.
			WithLabelValues(fromState).Dec()
	}

	// Since StateDisconnected is the final state, after which the
	// endpoint is gone, we should not increment metrics for this state.
	if toState != "" && toState != StateDisconnected {
		metrics.EndpointStateCount.
			WithLabelValues(toState).Inc()
	}
	return true
}

// BuilderSetStateLocked modifies the endpoint's state
// endpoint.Mutex must be held
// endpoint buildMutex must be held!
func (e *Endpoint) BuilderSetStateLocked(toState, reason string) bool {
	// Validate the state transition.
	fromState := e.state
	switch fromState { // From state
	case StateCreating, StateWaitingForIdentity, StateReady, StateDisconnecting, StateDisconnected:
		// No valid transitions for the builder
	case StateWaitingToRegenerate, StateRestoring:
		switch toState {
		// Builder transitions the endpoint from
		// waiting-to-regenerate state to regenerating state
		// right after acquiring the endpoint lock, and while
		// endpoint's build mutex is held. All changes to
		// cilium and endpoint configuration, policy as well
		// as the existing set of security identities will be
		// reconsidered after this point, i.e., even if some
		// of them are changed regeneration need not be queued
		// if the endpoint is already in waiting-to-regenerate
		// state.
		case StateRegenerating:
			goto OKState
		// Transition to ReadyState is not supported, but is
		// attempted when a regeneration is competed, and another
		// regeneration has been queued in the meanwhile. So this
		// is expected and will not be logged as an error or warning.
		case StateReady:
			return false
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
		// skipped (but not worth logging for, as this is
		// normal, see above).
		case StateReady:
			goto OKState
		}
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)

	if fromState != "" {
		metrics.EndpointStateCount.
			WithLabelValues(fromState).Dec()
	}

	// Since StateDisconnected is the final state, after which the
	// endpoint is gone, we should not increment metrics for this state.
	if toState != "" && toState != StateDisconnected {
		metrics.EndpointStateCount.
			WithLabelValues(toState).Inc()
	}
	return true
}

// OnProxyPolicyUpdate is a callback used to update the Endpoint's
// proxyPolicyRevision when the specified revision has been applied in the
// proxy.
func (e *Endpoint) OnProxyPolicyUpdate(revision uint64) {
	// NOTE: unconditionalLock is used here because this callback has no way of reporting an error
	e.unconditionalLock()
	if revision > e.proxyPolicyRevision {
		e.proxyPolicyRevision = revision
	}
	e.unlock()
}

// getProxyStatisticsLocked gets the ProxyStatistics for the flows with the
// given characteristics, or adds a new one and returns it.
// Must be called with e.proxyStatisticsMutex held.
func (e *Endpoint) getProxyStatisticsLocked(key string, l7Protocol string, port uint16, ingress bool) *models.ProxyStatistics {
	if e.proxyStatistics == nil {
		e.proxyStatistics = make(map[string]*models.ProxyStatistics)
	}

	proxyStats, ok := e.proxyStatistics[key]
	if !ok {
		var location string
		if ingress {
			location = models.ProxyStatisticsLocationIngress
		} else {
			location = models.ProxyStatisticsLocationEgress
		}
		proxyStats = &models.ProxyStatistics{
			Location: location,
			Port:     int64(port),
			Protocol: l7Protocol,
			Statistics: &models.RequestResponseStatistics{
				Requests:  &models.MessageForwardingStatistics{},
				Responses: &models.MessageForwardingStatistics{},
			},
		}

		e.proxyStatistics[key] = proxyStats
	}

	return proxyStats
}

// UpdateProxyStatistics updates the Endpoint's proxy  statistics to account
// for a new observed flow with the given characteristics.
func (e *Endpoint) UpdateProxyStatistics(l4Protocol string, port uint16, ingress, request bool, verdict accesslog.FlowVerdict) {
	e.proxyStatisticsMutex.Lock()
	defer e.proxyStatisticsMutex.Unlock()

	key := policy.ProxyID(e.ID, ingress, l4Protocol, port)
	proxyStats, ok := e.proxyStatistics[key]
	if !ok {
		e.getLogger().WithField(logfields.L4PolicyID, key).Warn("Proxy stats not found when updating")
		return
	}

	var stats *models.MessageForwardingStatistics
	if request {
		stats = proxyStats.Statistics.Requests
	} else {
		stats = proxyStats.Statistics.Responses
	}

	stats.Received++
	metrics.ProxyReceived.Inc()
	metrics.ProxyPolicyL7Total.WithLabelValues("received").Inc()

	switch verdict {
	case accesslog.VerdictForwarded:
		stats.Forwarded++
		metrics.ProxyForwarded.Inc()
		metrics.ProxyPolicyL7Total.WithLabelValues("forwarded").Inc()
	case accesslog.VerdictDenied:
		stats.Denied++
		metrics.ProxyDenied.Inc()
		metrics.ProxyPolicyL7Total.WithLabelValues("denied").Inc()
	case accesslog.VerdictError:
		stats.Error++
		metrics.ProxyParseErrors.Inc()
		metrics.ProxyPolicyL7Total.WithLabelValues("parse_errors").Inc()
	}
}

// APICanModify determines whether API requests from a user are allowed to
// modify this endpoint.
func APICanModify(e *Endpoint) error {
	if e.IsInit() {
		return nil
	}
	if e.OpLabels.OrchestrationIdentity.IsReserved() {
		return fmt.Errorf("endpoint may not be associated reserved labels")
	}
	return nil
}

func (e *Endpoint) getIDandLabels() string {
	e.unconditionalRLock()
	defer e.runlock()

	labels := ""
	if e.SecurityIdentity != nil {
		labels = e.SecurityIdentity.Labels.String()
	}

	return fmt.Sprintf("%d (%s)", e.ID, labels)
}

// MetadataResolverCB provides an implementation for resolving the endpoint
// metadata for an endpoint such as the associated labels and annotations.
type MetadataResolverCB func(ns, podName string) (identityLabels labels.Labels, infoLabels labels.Labels, annotations map[string]string, err error)

// RunMetadataResolver starts a controller associated with the received
// endpoint which will periodically attempt to resolve the metadata for the
// endpoint and update the endpoint with the related. It stops resolving after
// either the first successful metadata resolution or when the endpoint is
// removed.
//
// This assumes that after the initial successful resolution, other mechanisms
// will handle updates (such as pkg/k8s/watchers informers).
func (e *Endpoint) RunMetadataResolver(resolveMetadata MetadataResolverCB) {
	done := make(chan struct{})
	controllerName := fmt.Sprintf("resolve-labels-%s", e.GetK8sNamespaceAndPodName())
	go func() {
		<-done
		e.controllers.RemoveController(controllerName)
	}()

	e.controllers.UpdateController(controllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				ns, podName := e.GetK8sNamespace(), e.GetK8sPodName()
				identityLabels, info, _, err := resolveMetadata(ns, podName)
				if err != nil {
					e.Logger(controllerName).WithError(err).Warning("Unable to fetch kubernetes labels")
					return err
				}
				e.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
					_, _, annotations, err := resolveMetadata(ns, podName)
					if err != nil {
						return "", err
					}
					return annotations[annotation.ProxyVisibility], nil
				})
				e.UpdateLabels(ctx, identityLabels, info, true)
				close(done)
				return nil
			},
			RunInterval: 30 * time.Second,
			Context:     e.aliveCtx,
		},
	)
}

// ModifyIdentityLabels changes the custom and orchestration identity labels of an endpoint.
// Labels can be added or deleted. If a label change is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(addLabels, delLabels pkgLabels.Labels) error {
	if err := e.lockAlive(); err != nil {
		return err
	}

	changed, err := e.OpLabels.ModifyIdentityLabels(addLabels, delLabels)
	if err != nil {
		e.unlock()
		return err
	}

	var rev int
	// If the client made a request to modify labels, even if there was
	// no new labels added or deleted then we can safely remove the init
	// label. This is a workaround to allow the cilium-docker plugin
	// to remove endpoints in 'init' state if the containers were not
	// started with any label.
	if len(addLabels) == 0 && len(delLabels) == 0 && e.IsInit() {
		idLabls := e.OpLabels.IdentityLabels()
		delete(idLabls, pkgLabels.IDNameInit)
		rev = e.replaceIdentityLabels(idLabls)
		changed = true
	}
	if changed {
		// Mark with StateWaitingForIdentity, it will be set to
		// StateWaitingToRegenerate after the identity resolution has been
		// completed
		e.setState(StateWaitingForIdentity, "Triggering identity resolution due to updated identity labels")

		e.identityRevision++
		rev = e.identityRevision
	}
	e.unlock()

	if changed {
		e.runIdentityResolver(context.Background(), rev, false)
	}
	return nil
}

// IsInit returns true if the endpoint still hasn't received identity labels,
// i.e. has the special identity with label reserved:init.
func (e *Endpoint) IsInit() bool {
	init, found := e.OpLabels.GetIdentityLabel(pkgLabels.IDNameInit)
	return found && init.Source == pkgLabels.LabelSourceReserved
}

// UpdateLabels is called to update the labels of an endpoint. Calls to this
// function do not necessarily mean that the labels actually changed. The
// container runtime layer will periodically synchronize labels.
//
// If a net label changed was performed, the endpoint will receive a new
// identity and will be regenerated. Both of these operations will happen in
// the background.
func (e *Endpoint) UpdateLabels(ctx context.Context, identityLabels, infoLabels pkgLabels.Labels, blocking bool) {
	log.WithFields(logrus.Fields{
		logfields.ContainerID:    e.GetShortContainerID(),
		logfields.EndpointID:     e.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	if err := e.lockAlive(); err != nil {
		e.logDisconnectedMutexAction(err, "when trying to refresh endpoint labels")
		return
	}

	e.replaceInformationLabels(infoLabels)
	// replace identity labels and update the identity if labels have changed
	rev := e.replaceIdentityLabels(identityLabels)
	e.unlock()
	if rev != 0 {
		e.runIdentityResolver(ctx, rev, blocking)
	}
}

func (e *Endpoint) identityResolutionIsObsolete(myChangeRev int) bool {
	// Check if the endpoint has since received a new identity revision, if
	// so, abort as a new resolution routine will have been started.
	if myChangeRev != e.identityRevision {
		return true
	}

	return false
}

// runIdentityResolver resolves the numeric identity for the set of labels that
// are currently configured on the endpoint.
//
// Must be called with e.Mutex NOT held.
func (e *Endpoint) runIdentityResolver(ctx context.Context, myChangeRev int, blocking bool) {
	if err := e.rlockAlive(); err != nil {
		// If a labels update and an endpoint delete API request arrive
		// in quick succession, this could occur; in that case, there's
		// no point updating the controller.
		e.getLogger().WithError(err).Info("Cannot run labels resolver")
		return
	}
	newLabels := e.OpLabels.IdentityLabels()
	e.runlock()
	scopedLog := e.getLogger().WithField(logfields.IdentityLabels, newLabels)

	// If we are certain we can resolve the identity without accessing the KV
	// store, do it first synchronously right now. This can reduce the number
	// of regenerations for the endpoint during its initialization.
	if blocking || identity.IdentityAllocationIsLocal(newLabels) {
		scopedLog.Info("Resolving identity labels (blocking)")

		err := e.identityLabelsChanged(ctx, myChangeRev)
		switch err {
		case ErrNotAlive:
			scopedLog.Debug("not changing endpoint identity because endpoint is in process of being removed")
			return
		default:
			if err != nil {
				scopedLog.WithError(err).Warn("Error changing endpoint identity")
			}
		}
	} else {
		scopedLog.Info("Resolving identity labels (non-blocking)")
	}

	ctrlName := fmt.Sprintf("resolve-identity-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				err := e.identityLabelsChanged(ctx, myChangeRev)
				switch err {
				case ErrNotAlive:
					e.getLogger().Debug("not changing endpoint identity because endpoint is in process of being removed")
					return controller.NewExitReason("Endpoint disappeared")
				default:
					return err
				}
			},
			RunInterval: 5 * time.Minute,
			Context:     e.aliveCtx,
		},
	)
}

func (e *Endpoint) identityLabelsChanged(ctx context.Context, myChangeRev int) error {
	if err := e.rlockAlive(); err != nil {
		return ErrNotAlive
	}
	newLabels := e.OpLabels.IdentityLabels()
	elog := e.getLogger().WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.IdentityLabels: newLabels,
	})

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.runlock()
		elog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return nil
	}

	if e.SecurityIdentity != nil && e.SecurityIdentity.Labels.Equals(newLabels) {
		// Sets endpoint state to ready if was waiting for identity
		if e.getState() == StateWaitingForIdentity {
			e.setState(StateReady, "Set identity for this endpoint")
		}
		e.runlock()
		elog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.runlock()
	elog.Debug("Resolving identity for labels")

	allocateCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	allocatedIdentity, _, err := e.allocator.AllocateIdentity(allocateCtx, newLabels, true)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %s", err)
		e.LogStatus(Other, Warning, fmt.Sprintf("%s (will retry)", err.Error()))
		return err
	}

	// When releasing identities after allocation due to either failure of
	// allocation or due a no longer used identity we want to operation to
	// continue even if the parent has given up. Enforce a timeout of two
	// minutes to avoid blocking forever but give plenty of time to release
	// the identity.
	releaseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	releaseNewlyAllocatedIdentity := func() {
		_, err := e.allocator.Release(releaseCtx, allocatedIdentity)
		if err != nil {
			// non fatal error as keys will expire after lease expires but log it
			elog.WithFields(logrus.Fields{logfields.Identity: allocatedIdentity.ID}).
				WithError(err).Warn("Unable to release newly allocated identity again")
		}
	}

	if err := e.lockAlive(); err != nil {
		releaseNewlyAllocatedIdentity()
		return err
	}

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.unlock()

		releaseNewlyAllocatedIdentity()

		return nil
	}

	// If endpoint has an old identity, defer release of it to the end of
	// the function after the endpoint structured has been unlocked again
	oldIdentity := e.SecurityIdentity
	if oldIdentity != nil {
		// The identity of the endpoint is changing, delay the use of
		// the identity by a grace period to give all other cluster
		// nodes a chance to adjust their policies first. This requires
		// to unlock the endpoit and then lock it again.
		//
		// If the identity change is from init -> *, don't delay the
		// use of the identity as we want the init duration to be as
		// short as possible.
		if allocatedIdentity.ID != oldIdentity.ID && oldIdentity.ID != identity.ReservedIdentityInit {
			e.unlock()

			elog.Debugf("Applying grace period before regeneration due to identity change")
			time.Sleep(option.Config.IdentityChangeGracePeriod)

			if err := e.lockAlive(); err != nil {
				releaseNewlyAllocatedIdentity()
				return err
			}

			// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
			if e.identityResolutionIsObsolete(myChangeRev) {
				e.unlock()
				releaseNewlyAllocatedIdentity()
				return nil
			}
		}
	}

	elog.WithFields(logrus.Fields{logfields.Identity: allocatedIdentity.StringID()}).
		Debug("Assigned new identity to endpoint")

	e.SetIdentity(allocatedIdentity, false)

	if oldIdentity != nil {
		_, err := e.allocator.Release(releaseCtx, oldIdentity)
		if err != nil {
			elog.WithFields(logrus.Fields{logfields.Identity: oldIdentity.ID}).
				WithError(err).Warn("Unable to release old endpoint identity")
		}
	}

	readyToRegenerate := false

	// Regeneration is only triggered once the endpoint ID has been
	// assigned. This ensures that on the initial creation, the endpoint is
	// not generated until the endpoint ID has been assigned. If the
	// identity is resolved before the endpoint ID is assigned, the
	// regeneration is deferred into endpointmanager.AddEndpoint(). If the
	// identity is not allocated yet when endpointmanager.AddEndpoint() is
	// called, the controller calling identityLabelsChanged() will trigger
	// the regeneration as soon as the identity is known.
	if e.ID != 0 {
		readyToRegenerate = e.setState(StateWaitingToRegenerate, "Triggering regeneration due to new identity")
	}

	// Unconditionally force policy recomputation after a new identity has been
	// assigned.
	e.forcePolicyComputation()

	e.unlock()

	if readyToRegenerate {
		e.Regenerate(&regeneration.ExternalRegenerationMetadata{Reason: "updated security labels"})
	}

	return nil
}

// SetPolicyRevision sets the endpoint's policy revision with the given
// revision.
func (e *Endpoint) SetPolicyRevision(rev uint64) {
	if err := e.lockAlive(); err != nil {
		return
	}
	e.setPolicyRevision(rev)
	e.unlock()
}

// setPolicyRevision sets the endpoint's policy revision with the given
// revision.
func (e *Endpoint) setPolicyRevision(rev uint64) {
	if rev <= e.policyRevision {
		return
	}

	now := time.Now()
	e.policyRevision = rev
	e.UpdateLogger(map[string]interface{}{
		logfields.DatapathPolicyRevision: e.policyRevision,
	})
	for ps := range e.policyRevisionSignals {
		select {
		case <-ps.ctx.Done():
			close(ps.ch)
			ps.done(now)
			delete(e.policyRevisionSignals, ps)
		default:
			if rev >= ps.wantedRev {
				close(ps.ch)
				ps.done(now)
				delete(e.policyRevisionSignals, ps)
			}
		}
	}
}

// cleanPolicySignals closes and removes all policy revision signals.
func (e *Endpoint) cleanPolicySignals() {
	now := time.Now()
	for w := range e.policyRevisionSignals {
		w.done(now)
		close(w.ch)
	}
	e.policyRevisionSignals = map[*policySignal]bool{}
}

// policySignal is used to mark when a wanted policy wantedRev is reached
type policySignal struct {
	// wantedRev specifies which policy revision the signal wants.
	wantedRev uint64
	// ch is the channel that signalizes once the policy revision wanted is reached.
	ch chan struct{}
	// ctx is the context for the policy signal request.
	ctx context.Context
	// done is a callback to call for this policySignal. It is in addition to the
	// ch above.
	done func(ts time.Time)
}

// WaitForPolicyRevision returns a channel that is closed when one or more of
// the following conditions have met:
//  - the endpoint is disconnected state
//  - the endpoint's policy revision reaches the wanted revision
// When the done callback is non-nil it will be called just before the channel is closed.
func (e *Endpoint) WaitForPolicyRevision(ctx context.Context, rev uint64, done func(ts time.Time)) <-chan struct{} {
	// NOTE: unconditionalLock is used here because this method handles endpoint in disconnected state on its own
	e.unconditionalLock()
	defer e.unlock()

	if done == nil {
		done = func(time.Time) {}
	}

	ch := make(chan struct{})
	if e.policyRevision >= rev || e.state == StateDisconnected {
		close(ch)
		done(time.Now())
		return ch
	}
	ps := &policySignal{
		wantedRev: rev,
		ctx:       ctx,
		ch:        ch,
		done:      done,
	}
	if e.policyRevisionSignals == nil {
		e.policyRevisionSignals = map[*policySignal]bool{}
	}
	e.policyRevisionSignals[ps] = true
	return ch
}

// IPs returns the slice of valid IPs for this endpoint.
func (e *Endpoint) IPs() []net.IP {
	ips := []net.IP{}
	if e.IPv4.IsSet() {
		ips = append(ips, e.IPv4.IP())
	}
	if e.IPv6.IsSet() {
		ips = append(ips, e.IPv6.IP())
	}
	return ips
}

// IsDisconnecting returns true if the endpoint is being disconnected or
// already disconnected
//
// This function must be called after re-acquiring the endpoint mutex to verify
// that the endpoint has not been removed in the meantime.
//
// endpoint.mutex must be held in read mode at least
func (e *Endpoint) IsDisconnecting() bool {
	return e.state == StateDisconnected || e.state == StateDisconnecting
}

// PinDatapathMap retrieves a file descriptor from the map ID from the API call
// and pins the corresponding map into the BPF file system.
func (e *Endpoint) PinDatapathMap() error {
	if err := e.lockAlive(); err != nil {
		return err
	}
	defer e.unlock()
	return e.pinDatapathMap()
}

// PinDatapathMap retrieves a file descriptor from the map ID from the API call
// and pins the corresponding map into the BPF file system.
func (e *Endpoint) pinDatapathMap() error {
	if e.datapathMapID == 0 {
		return nil
	}

	mapFd, err := bpf.MapFdFromID(e.datapathMapID)
	if err != nil {
		return err
	}
	defer unix.Close(mapFd)

	err = bpf.ObjPin(mapFd, e.BPFIpvlanMapPath())

	if err == nil {
		e.isDatapathMapPinned = true
	}

	return err
}

func (e *Endpoint) syncEndpointHeaderFile(reasons []string) {
	e.buildMutex.Lock()
	defer e.buildMutex.Unlock()

	if err := e.lockAlive(); err != nil {
		// endpoint was removed in the meanwhile, return
		return
	}
	defer e.unlock()

	if err := e.writeHeaderfile(e.StateDirectoryPath()); err != nil {
		e.getLogger().WithFields(logrus.Fields{
			logfields.Reason: reasons,
		}).WithError(err).Warning("could not sync header file")
	}
}

// SyncEndpointHeaderFile it bumps the current DNS History information for the
// endpoint in the lxc_config.h file.
func (e *Endpoint) SyncEndpointHeaderFile() error {
	if err := e.lockAlive(); err != nil {
		// endpoint was removed in the meanwhile, return
		return nil
	}
	defer e.unlock()

	if e.dnsHistoryTrigger == nil {
		t, err := trigger.NewTrigger(trigger.Parameters{
			Name:        "sync_endpoint_header_file",
			MinInterval: 5 * time.Second,
			TriggerFunc: func(reasons []string) { e.syncEndpointHeaderFile(reasons) },
		})
		if err != nil {
			return fmt.Errorf(
				"Sync Endpoint header file trigger for endpoint cannot be activated: %s",
				err)
		}
		e.dnsHistoryTrigger = t
	}
	e.dnsHistoryTrigger.Trigger()
	return nil
}

type ipReleaser interface {
	ReleaseIP(net.IP) error
}

type monitorOwner interface {
	NotifyMonitorDeleted(e *Endpoint)
}

// Delete cleans up all resources associated with this endpoint, including the
// following:
// * all goroutines managed by this Endpoint (EventQueue, Controllers)
// * removal from the endpointmanager, resulting in new events not taking effect
// on this endpoint
// * cleanup of datapath state (BPF maps, proxy configuration, directories)
// * releasing IP addresses allocated for the endpoint
// * releasing of the reference to its allocated security identity
func (e *Endpoint) Delete(monitor monitorOwner, ipam ipReleaser, manager endpointManager, conf DeleteConfig) []error {
	errs := []error{}

	// Since the endpoint is being deleted, we no longer need to run events
	// in its event queue. This is a no-op if the queue has already been
	// closed elsewhere.
	e.eventQueue.Stop()

	// Wait for the queue to be drained in case an event which is currently
	// running for the endpoint tries to acquire the lock - we cannot be sure
	// what types of events will be pushed onto the EventQueue for an endpoint
	// and when they will happen. After this point, no events for the endpoint
	// will be processed on its EventQueue, specifically regenerations.
	e.eventQueue.WaitToBeDrained()

	// Given that we are deleting the endpoint and that no more builds are
	// going to occur for this endpoint, close the channel which signals whether
	// the endpoint has its BPF program compiled or not to avoid it persisting
	// if anything is blocking on it. If a delete request has already been
	// enqueued for this endpoint, this is a no-op.
	e.closeBPFProgramChannel()

	// Lock out any other writers to the endpoint.  In case multiple delete
	// requests have been enqueued, have all of them except the first
	// return here. Ignore the request if the endpoint is already
	// disconnected.
	if err := e.lockAlive(); err != nil {
		return []error{}
	}
	e.aliveCancel()
	e.setState(StateDisconnecting, "Deleting endpoint")

	// Remove the endpoint before we clean up. This ensures it is no longer
	// listed or queued for rebuilds.
	e.Unexpose(manager)

	defer func() {
		monitor.NotifyMonitorDeleted(e)
	}()

	// If dry mode is enabled, no changes to BPF maps are performed
	if !option.Config.DryMode {
		if errs2 := lxcmap.DeleteElement(e); errs2 != nil {
			errs = append(errs, errs2...)
		}

		if errs2 := e.deleteMaps(); errs2 != nil {
			errs = append(errs, errs2...)
		}
	}

	if !conf.NoIPRelease {
		if option.Config.EnableIPv4 {
			if err := ipam.ReleaseIP(e.IPv4.IP()); err != nil {
				errs = append(errs, fmt.Errorf("unable to release ipv4 address: %s", err))
			}
		}
		if option.Config.EnableIPv6 {
			if err := ipam.ReleaseIP(e.IPv6.IP()); err != nil {
				errs = append(errs, fmt.Errorf("unable to release ipv6 address: %s", err))
			}
		}
	}

	completionCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	proxyWaitGroup := completion.NewWaitGroup(completionCtx)

	errs = append(errs, e.leaveLocked(proxyWaitGroup, conf)...)
	e.unlock()

	err := e.waitForProxyCompletions(proxyWaitGroup)
	if err != nil {
		errs = append(errs, fmt.Errorf("unable to remove proxy redirects: %s", err))
	}
	cancel()

	if option.Config.IsFlannelMasterDeviceSet() &&
		option.Config.FlannelUninstallOnExit {
		e.DeleteBPFProgramLocked()
	}

	return errs
}

// GetProxyInfoByFields returns the ID, IPv4 address, IPv6 address, labels,
// SHA of labels, and identity of the endpoint. Returns an error if the endpoint
// is in the process of being deleted / has been deleted.
func (e *Endpoint) GetProxyInfoByFields() (uint64, string, string, []string, string, uint64, error) {
	// We use unconditional locking here because we explicitly handle state
	// in which the endpoint is being deleted.
	e.unconditionalRLock()
	defer e.runlock()
	var err error
	if e.IsDisconnecting() {
		err = fmt.Errorf("endpoint is in the process of being deleted")
	}
	return e.GetID(), e.GetIPv4Address(), e.GetIPv6Address(), e.GetLabels(), e.GetLabelsSHA(), uint64(e.GetIdentity()), err
}

// RegenerateAfterCreation handles the first regeneration of an endpoint after
// it is created.
// After a call to `Regenerate` on the endpoint is made, `endpointStartFunc`
// is invoked - this can be used as a callback to expose the endpoint to other
// subsystems if needed.
// If syncBuild is true, this function waits for specific conditions until
// returning:
// * if the endpoint has a sidecar proxy, it waits for the endpoint's BPF
// program to be generated for the first time.
// * otherwise, waits for the endpoint to complete its first full regeneration.
func (e *Endpoint) RegenerateAfterCreation(ctx context.Context, syncBuild bool) error {
	if err := e.lockAlive(); err != nil {
		return fmt.Errorf("endpoint was deleted while processing the request")
	}

	build := e.getState() == StateReady
	if build {
		e.setState(StateWaitingToRegenerate, "Identity is known at endpoint creation time")
	}
	e.unlock()

	if build {
		// Do not synchronously regenerate the endpoint when first creating it.
		// We have custom logic later for waiting for specific checkpoints to be
		// reached upon regeneration later (checking for when BPF programs have
		// been compiled), as opposed to waiting for the entire regeneration to
		// be complete (including proxies being configured). This is done to
		// avoid a chicken-and-egg problem with L7 policies are imported which
		// select the endpoint being generated, as when such policies are
		// imported, regeneration blocks on waiting for proxies to be
		// configured. When Cilium is used with Istio, though, the proxy is
		// started as a sidecar, and is not launched yet when this specific code
		// is executed; if we waited for regeneration to be complete, including
		// proxy configuration, this code would effectively deadlock addition
		// of endpoints.
		e.Regenerate(&regeneration.ExternalRegenerationMetadata{
			Reason:        "Initial build on endpoint creation",
			ParentContext: ctx,
		})
	}

	// Wait for endpoint to be in "ready" state if specified in API call.
	if !syncBuild {
		return nil
	}

	return e.waitForFirstRegeneration(ctx)
}

func (e *Endpoint) waitForFirstRegeneration(ctx context.Context) error {
	e.getLogger().Info("Waiting for endpoint to be generated")

	// Default timeout for PUT /endpoint/{id} is 60 seconds, so put timeout
	// in this function a bit below that timeout. If the timeout for clients
	// in API is below this value, they will get a message containing
	// "context deadline exceeded" if the operation takes longer than the
	// client's configured timeout value.
	ctx, cancel := context.WithTimeout(ctx, EndpointGenerationTimeout)

	// Check the endpoint's state and labels periodically.
	ticker := time.NewTicker(1 * time.Second)
	defer func() {
		cancel()
		ticker.Stop()
	}()

	// Wait for any successful BPF regeneration, which is indicated by any
	// positive policy revision (>0). As long as at least one BPF
	// regeneration is successful, the endpoint has network connectivity
	// so we can return from the creation API call.
	revCh := e.WaitForPolicyRevision(ctx, 1, nil)

	for {
		select {
		case <-revCh:
			if ctx.Err() == nil {
				// At least one BPF regeneration has successfully completed.
				return nil
			}

		case <-ctx.Done():
		case <-ticker.C:
			if err := e.rlockAlive(); err != nil {
				return fmt.Errorf("endpoint was deleted while waiting for initial endpoint generation to complete")
			}
			hasSidecarProxy := e.HasSidecarProxy()
			e.runlock()
			if hasSidecarProxy && e.bpfProgramInstalled() {
				// If the endpoint is determined to have a sidecar proxy,
				// return immediately to let the sidecar container start,
				// in case it is required to enforce L7 rules.
				e.getLogger().Info("Endpoint has sidecar proxy, returning from synchronous creation request before regeneration has succeeded")
				return nil
			}
		}

		if ctx.Err() != nil {
			return fmt.Errorf("timeout while waiting for initial endpoint generation to complete")
		}
	}
}

// SetDefaultConfiguration sets the default configuration options for its
// boolean configuration options and for policy enforcement based off of the
// global policy enforcement configuration options. If restore is true, then
// the configuration option to keep endpoint configuration during endpoint
// restore is checked, and if so, this is a no-op.
func (e *Endpoint) SetDefaultConfiguration(restore bool) {
	e.unconditionalLock()
	defer e.unlock()

	if restore && option.Config.KeepConfig {
		return
	}
	e.setDefaultPolicyConfig()
}

func (e *Endpoint) setDefaultPolicyConfig() {
	e.SetDefaultOpts(option.Config.Opts)
	alwaysEnforce := policy.GetPolicyEnabled() == option.AlwaysEnforce
	e.desiredPolicy.IngressPolicyEnabled = alwaysEnforce
	e.desiredPolicy.EgressPolicyEnabled = alwaysEnforce
}

// WaitUntilExposed will return once the endpoint is exposed in the endpoint
// manager. It returns an error in case the given context expires of if the
// endpoint is deleted in the meanwhile, i.e., the endpoint's aliveCtx is
// canceled.
func (e *Endpoint) WaitUntilExposed(ctx context.Context) error {
	select {
	case <-e.exposed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-e.aliveCtx.Done():
		return e.aliveCtx.Err()
	}
}
