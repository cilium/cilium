// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2021 Authors of Cilium

package endpoint

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/link"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/notifications"
	"github.com/cilium/cilium/pkg/node"
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

// State is an enumeration for possible endpoint states.
type State string

const (
	// StateWaitingForIdentity is used to set if the endpoint is waiting
	// for an identity from the KVStore.
	StateWaitingForIdentity = State(models.EndpointStateWaitingForIdentity)

	// StateReady specifies if the endpoint is ready to be used.
	StateReady = State(models.EndpointStateReady)

	// StateWaitingToRegenerate specifies when the endpoint needs to be regenerated, but regeneration has not started yet.
	StateWaitingToRegenerate = State(models.EndpointStateWaitingToRegenerate)

	// StateRegenerating specifies when the endpoint is being regenerated.
	StateRegenerating = State(models.EndpointStateRegenerating)

	// StateDisconnecting indicates that the endpoint is being disconnected
	StateDisconnecting = State(models.EndpointStateDisconnecting)

	// StateDisconnected is used to set the endpoint is disconnected.
	StateDisconnected = State(models.EndpointStateDisconnected)

	// StateRestoring is used to set the endpoint is being restored.
	StateRestoring = State(models.EndpointStateRestoring)

	// StateInvalid is used when an endpoint failed during creation due to
	// invalid data.
	StateInvalid = State(models.EndpointStateInvalid)

	// IpvlanMapName specifies the tail call map for EP on egress used with ipvlan.
	IpvlanMapName = "cilium_lxc_ipve_"
)

// compile time interface check
var _ notifications.RegenNotificationInfo = (*Endpoint)(nil)

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

	// createdAt stores the time the endpoint was created. This value is
	// recalculated on endpoint restore.
	createdAt time.Time

	// mutex protects write operations to this endpoint structure
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

	// ifName is the name of the host facing interface (veth pair) which
	// connects into the endpoint
	ifName string

	// ifIndex is the interface index of the host face interface (veth pair)
	ifIndex int

	// OpLabels is the endpoint's label configuration
	//
	// FIXME: Rename this field to Labels
	OpLabels labels.OpLabels

	// identityRevision is incremented each time the identity label
	// information of the endpoint has changed
	identityRevision int

	// bps is the egress rate of the endpoint
	bps uint64

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

	// policyMapPressureGauge is a metric to track and report the pressure over
	// policyMap.
	policyMapPressureGauge *metrics.GaugeWithThreshold

	// Options determine the datapath configuration of the endpoint.
	Options *option.IntOptions

	// status contains the last n state transitions this endpoint went through
	status *EndpointStatus

	// DNSRules is the collection of current endpoint-specific DNS proxy
	// rules. These can be restored during Cilium restart.
	DNSRules restore.DNSRules

	// DNSHistory is the collection of still-valid DNS responses intercepted for
	// this endpoint.
	DNSHistory *fqdn.DNSCache

	// DNSZombies is the collection of DNS IPs that have expired in or been
	// evicted from DNSHistory. They are held back from deletion until we can
	// confirm that no existing connection is using them.
	DNSZombies *fqdn.DNSZombieMappings

	// dnsHistoryTrigger is the trigger to write down the ep_config.h to make
	// sure that restores when DNS policy is in there are correct
	dnsHistoryTrigger *trigger.Trigger

	// state is the state the endpoint is in. See setState()
	state State

	// bpfHeaderfileHash is the hash of the last BPF headerfile that has been
	// compiled and installed.
	bpfHeaderfileHash string

	// K8sPodName is the Kubernetes pod name of the endpoint
	K8sPodName string

	// K8sNamespace is the Kubernetes namespace of the endpoint
	K8sNamespace string

	// pod
	pod *slim_corev1.Pod

	// k8sPorts contains container ports associated in the pod.
	// It is used to enforce k8s network policies with port names.
	k8sPorts policy.NamedPortMap

	// logLimiter rate limits potentially repeating warning logs
	logLimiter logging.Limiter

	// k8sPortsSet keep track when k8sPorts was set at least one time.
	hasK8sMetadata bool

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
	// This must only be accessed with atomic.LoadPointer/StorePointer.
	// 'mutex' must be Lock()ed to synchronize stores. No lock needs to be held
	// when loading this pointer.
	logger unsafe.Pointer

	// policyLogger is a logrus object with fields set to report an endpoints information.
	// This must only be accessed with atomic LoadPointer/StorePointer.
	// 'mutex' must be Lock()ed to synchronize stores. No lock needs to be held
	// when loading this pointer.
	policyLogger unsafe.Pointer

	// controllers is the list of async controllers syncing the endpoint to
	// other resources
	controllers *controller.Manager

	// realizedRedirects maps the ID of each proxy redirect that has been
	// successfully added into a proxy for this endpoint, to the redirect's
	// proxy port number.
	// You must hold Endpoint.mutex to read or write it.
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

	// skippedRegenerationLevel is the DatapathRegenerationLevel of the regeneration event that
	// was skipped due to another regeneration event already being queued, as indicated by
	// state. A lower-level current regeneration is bumped to this level to cover for the
	// skipped regeneration levels.
	skippedRegenerationLevel regeneration.DatapathRegenerationLevel

	// DatapathConfiguration is the endpoint's datapath configuration as
	// passed in via the plugin that created the endpoint, e.g. the CNI
	// plugin which performed the plumbing will enable certain datapath
	// features according to the mode selected.
	DatapathConfiguration models.EndpointDatapathConfiguration

	aliveCtx        context.Context
	aliveCancel     context.CancelFunc
	regenFailedChan chan struct{}

	allocator cache.IdentityAllocator

	isHost bool

	noTrackPort uint16
}

// EndpointSyncControllerName returns the controller name to synchronize
// endpoint in to kubernetes.
func EndpointSyncControllerName(epID uint16) string {
	return fmt.Sprintf("sync-to-k8s-ciliumendpoint (%v)", epID)
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

func (e *Endpoint) IsHost() bool {
	return e.isHost
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
func NewEndpointWithState(owner regeneration.Owner, proxy EndpointProxy, allocator cache.IdentityAllocator, ID uint16, state State) *Endpoint {
	ep := createEndpoint(owner, proxy, allocator, ID, "")
	ep.state = state
	ep.eventQueue = eventqueue.NewEventQueueBuffered(fmt.Sprintf("endpoint-%d", ID), option.Config.EndpointQueueSize)

	ep.UpdateLogger(nil)

	ep.eventQueue.Run()

	return ep
}

func createEndpoint(owner regeneration.Owner, proxy EndpointProxy, allocator cache.IdentityAllocator, ID uint16, ifName string) *Endpoint {
	ep := &Endpoint{
		owner:           owner,
		ID:              ID,
		createdAt:       time.Now(),
		proxy:           proxy,
		ifName:          ifName,
		OpLabels:        labels.NewOpLabels(),
		DNSRules:        nil,
		DNSHistory:      fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		DNSZombies:      fqdn.NewDNSZombieMappings(option.Config.ToFQDNsMaxDeferredConnectionDeletes),
		state:           "",
		status:          NewEndpointStatus(),
		hasBPFProgram:   make(chan struct{}, 0),
		desiredPolicy:   policy.NewEndpointPolicy(owner.GetPolicyRepository()),
		controllers:     controller.NewManager(),
		regenFailedChan: make(chan struct{}, 1),
		allocator:       allocator,
		logLimiter:      logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
		noTrackPort:     0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	ep.aliveCancel = cancel
	ep.aliveCtx = ctx

	ep.realizedPolicy = ep.desiredPolicy

	ep.SetDefaultOpts(option.Config.Opts)

	return ep
}

// CreateHostEndpoint creates the endpoint corresponding to the host.
func CreateHostEndpoint(owner regeneration.Owner, proxy EndpointProxy, allocator cache.IdentityAllocator) (*Endpoint, error) {
	ifName := option.Config.HostDevice

	mac, err := link.GetHardwareAddr(ifName)
	if err != nil {
		return nil, err
	}

	ep := createEndpoint(owner, proxy, allocator, 0, ifName)
	ep.isHost = true
	ep.mac = mac
	ep.nodeMAC = mac
	ep.DatapathConfiguration = NewDatapathConfiguration()

	ep.setState(StateWaitingForIdentity, "Endpoint creation")

	return ep, nil
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

// HostInterface returns the name of the link-layer interface used for
// communicating with the endpoint from the host (if available).
//
// In some datapath modes, it may return an empty string as there is no unique
// host netns network interface for this endpoint.
func (e *Endpoint) HostInterface() string {
	if e.HasIpvlanDataPath() {
		return ""
	}
	return e.ifName
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

// GetIdentityLocked is identical to GetIdentity() but assumes that a.mutex is
// already held. This function is obsolete and should no longer be used.
func (e *Endpoint) GetIdentityLocked() identity.NumericIdentity {
	return e.getIdentity()
}

// GetIdentity returns the numeric security identity of the endpoint
func (e *Endpoint) GetIdentity() identity.NumericIdentity {
	e.unconditionalRLock()
	defer e.runlock()

	return e.getIdentity()
}

func (e *Endpoint) getIdentity() identity.NumericIdentity {
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

	v, ok := e.desiredPolicy.PolicyMapState[keyToLookup]
	return ok && !v.IsDeny
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

// ApplyOpts tries to lock endpoint, applies the given options to the
// endpoint's options and returns true if there were any options changed.
func (e *Endpoint) ApplyOpts(opts option.OptionMap) (bool, error) {
	if err := e.lockAlive(); err != nil {
		return false, err
	}
	defer e.unlock()
	changed := e.applyOptsLocked(opts)
	return changed, nil
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
	if option.Config.Debug {
		e.Options.SetValidated(option.DebugPolicy, option.OptionEnabled)
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

// parseBase64ToEndpoint parses the endpoint stored in the given base64 byte slice.
func parseBase64ToEndpoint(b []byte, ep *Endpoint) error {
	jsonBytes := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(jsonBytes, b)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(jsonBytes[:n], ep); err != nil {
		return fmt.Errorf("error unmarshaling serializableEndpoint from base64 representation: %s", err)
	}

	return nil
}

// FilterEPDir returns a list of directories' names that possible belong to an endpoint.
func FilterEPDir(dirFiles []os.DirEntry) []string {
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

// parseEndpoint parses the given bEp which is in the form of:
// common.CiliumCHeaderPrefix + common.Version + ":" + endpointBase64
// Note that the parse'd endpoint's identity is only partially restored. The
// caller must call `SetIdentity()` to make the returned endpoint's identity useful.
func parseEndpoint(ctx context.Context, owner regeneration.Owner, bEp []byte) (*Endpoint, error) {
	// TODO: Provide a better mechanism to update from old version once we bump
	// TODO: cilium version.
	epSlice := bytes.Split(bEp, []byte{':'})
	if len(epSlice) != 2 {
		return nil, fmt.Errorf("invalid format %q. Should contain a single ':'", bEp)
	}
	ep := Endpoint{
		owner: owner,
	}

	if err := parseBase64ToEndpoint(epSlice[1], &ep); err != nil {
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

	ctx, cancel := context.WithCancel(ctx)
	ep.aliveCancel = cancel
	ep.aliveCtx = ctx

	// If host label is present, it's the host endpoint.
	ep.isHost = ep.HasLabels(labels.LabelHost)

	if ep.isHost {
		// Overwrite datapath configuration with the current agent configuration.
		ep.DatapathConfiguration = NewDatapathConfiguration()
	}

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

// NewDatapathConfiguration return the default endpoint datapath configuration
// based on whether per-endpoint routes are enabled.
func NewDatapathConfiguration() models.EndpointDatapathConfiguration {
	config := models.EndpointDatapathConfiguration{}
	if option.Config.EnableEndpointRoutes {
		// Indicate to insert a per endpoint route instead of routing
		// via cilium_host interface
		config.InstallEndpointRoute = true

		// Since routing occurs via endpoint interface directly, BPF
		// program is needed on that device at egress as BPF program on
		// cilium_host interface is bypassed
		config.RequireEgressProg = true

		// Delegate routing to the Linux stack rather than tail-calling
		// between BPF programs.
		disabled := false
		config.RequireRouting = &disabled
	}
	return config
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
// Must be called with endpoint.mutex RLock()ed.
func (e *Endpoint) LogStatusOKLocked(typ StatusType, msg string) {
	e.logStatusLocked(typ, OK, msg)
}

// logStatusLocked logs a status message.
// Must be called with endpoint.mutex RLock()ed.
func (e *Endpoint) logStatusLocked(typ StatusType, code StatusCode, msg string) {
	e.status.indexMU.Lock()
	defer e.status.indexMU.Unlock()
	sts := &statusLogMsg{
		Status: Status{
			Code:  code,
			Msg:   msg,
			Type:  typ,
			State: string(e.state),
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
		Reason:            "endpoint was updated via API",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
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
				regen, err := e.SetRegenerateStateIfAlive(regenCtx)
				if err != nil {
					return err
				}
				if regen {
					e.Regenerate(regenCtx)
					return nil
				}
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
func (e *Endpoint) HasLabels(l labels.Labels) bool {
	e.unconditionalRLock()
	defer e.runlock()

	return e.hasLabelsRLocked(l)
}

// hasLabelsRLocked returns whether endpoint e contains all labels l. Will
// return 'false' if any label in l is not in the endpoint's labels.
// e.mutex must be RLock()ed.
func (e *Endpoint) hasLabelsRLocked(l labels.Labels) bool {
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
// Must be called with e.mutex.Lock().
func (e *Endpoint) replaceInformationLabels(l labels.Labels) {
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
// Must be called with e.mutex.Lock().
func (e *Endpoint) replaceIdentityLabels(l labels.Labels) int {
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

	// Remove policy references from shared policy structures
	e.desiredPolicy.Detach()
	e.realizedPolicy.Detach()

	// Remove restored rules of cleaned endpoint
	e.owner.RemoveRestoredDNSRules(e.ID)

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
		// Restored endpoint may be created with a reserved identity of 5
		// (init), which is not registered in the identity manager and
		// therefore doesn't need to be removed.
		if e.SecurityIdentity.ID != identity.ReservedIdentityInit {
			identitymanager.Remove(e.SecurityIdentity)
		}

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

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	e.unconditionalRLock()
	ns := e.K8sNamespace
	e.runlock()
	return ns
}

// SetPod sets the pod related to this endpoint.
func (e *Endpoint) SetPod(pod *slim_corev1.Pod) {
	e.unconditionalLock()
	e.pod = pod
	e.unlock()
}

// GetPod retrieves the pod related to this endpoint
func (e *Endpoint) GetPod() *slim_corev1.Pod {
	e.unconditionalRLock()
	pod := e.pod
	e.runlock()
	return pod
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

// SetK8sMetadata sets the k8s container ports specified by kubernetes.
// Note that once put in place, the new k8sPorts is never changed,
// so that the map can be used concurrently without keeping locks.
// Reading the 'e.k8sPorts' member (the "map pointer") *itself* requires the endpoint lock!
// Can't really error out as that might break backwards compatibility.
func (e *Endpoint) SetK8sMetadata(containerPorts []slim_corev1.ContainerPort) error {
	k8sPorts := make(policy.NamedPortMap, len(containerPorts))
	for _, cp := range containerPorts {
		if cp.Name == "" {
			continue // silently skip unnamed ports
		}
		err := k8sPorts.AddPort(cp.Name, int(cp.ContainerPort), string(cp.Protocol))
		if err != nil {
			e.getLogger().WithError(err).Warning("Adding named port failed")
			continue
		}
	}
	if len(k8sPorts) == 0 {
		k8sPorts = nil // nil map with no storage
	}
	e.mutex.Lock()
	e.hasK8sMetadata = true
	e.k8sPorts = k8sPorts
	e.mutex.Unlock()
	return nil
}

// GetK8sPorts returns the k8sPorts, which must not be modified by the caller
func (e *Endpoint) GetK8sPorts() (k8sPorts policy.NamedPortMap, err error) {
	err = e.rlockAlive()
	if err != nil {
		return nil, err
	}
	k8sPorts = e.k8sPorts
	e.mutex.RUnlock()
	return k8sPorts, nil
}

// HaveK8sMetadata returns true once hasK8sMetadata was set
func (e *Endpoint) HaveK8sMetadata() (metadataSet bool) {
	e.mutex.RLock()
	metadataSet = e.hasK8sMetadata
	e.mutex.RUnlock()
	return
}

// K8sNamespaceAndPodNameIsSet returns true if the pod name is set
func (e *Endpoint) K8sNamespaceAndPodNameIsSet() bool {
	e.unconditionalLock()
	podName := e.getK8sNamespaceAndPodName()
	e.unlock()
	return podName != "" && podName != "/"
}

// getState returns the endpoint's state
// endpoint.mutex may only be rlockAlive()ed
func (e *Endpoint) getState() State {
	return e.state
}

// GetState returns the endpoint's state
// endpoint.mutex may only be rlockAlive()ed
func (e *Endpoint) GetState() State {
	e.unconditionalRLock()
	defer e.runlock()
	return e.getState()
}

// SetState modifies the endpoint's state. Returns true only if endpoints state
// was changed as requested
func (e *Endpoint) SetState(toState State, reason string) bool {
	e.unconditionalLock()
	defer e.unlock()

	return e.setState(toState, reason)
}

func (e *Endpoint) setState(toState State, reason string) bool {
	// Validate the state transition.
	fromState := e.state

	switch fromState { // From state
	case "": // Special case for capturing initial state transitions like
		// nil --> StateWaitingForIdentity, StateRestoring
		switch toState {
		case StateWaitingForIdentity, StateRestoring:
			goto OKState
		}
	case StateWaitingForIdentity:
		switch toState {
		case StateReady, StateDisconnecting, StateInvalid:
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
	case StateDisconnected, StateInvalid:
		// No valid transitions, as disconnected and invalid are terminal
		// states for the endpoint.
	case StateWaitingToRegenerate:
		switch toState {
		// Note that transitions to StateWaitingToRegenerate are not allowed,
		// as callers of this function enqueue regenerations if 'true' is
		// returned. We don't want to return 'true' for the case of
		// transitioning to StateWaitingToRegenerate, as this means that a
		// regeneration is already queued up. Callers would then queue up
		// another unneeded regeneration, which is undesired.
		// Transition to StateWaitingForIdentity is also not allowed as that
		// will break the ensuing regeneration.
		case StateDisconnecting, StateRestoring:
			goto OKState
		// Don't log these state transition being invalid below so that we don't
		// put warnings in the logs for a case which does not result in incorrect
		// behavior.
		case StateWaitingForIdentity, StateWaitingToRegenerate:
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
			WithLabelValues(string(fromState)).Dec()
	}

	// Since StateDisconnected and StateInvalid are final states, after which
	// the endpoint is gone or doesn't exist, we should not increment metrics
	// for these states.
	if toState != "" && toState != StateDisconnected && toState != StateInvalid {
		metrics.EndpointStateCount.
			WithLabelValues(string(toState)).Inc()
	}
	return true
}

// BuilderSetStateLocked modifies the endpoint's state
// endpoint.mutex must be Lock()ed
// endpoint buildMutex must be held!
func (e *Endpoint) BuilderSetStateLocked(toState State, reason string) bool {
	// Validate the state transition.
	fromState := e.state
	switch fromState { // From state
	case StateWaitingForIdentity, StateReady, StateDisconnecting, StateDisconnected, StateInvalid:
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
			WithLabelValues(string(fromState)).Dec()
	}

	// Since StateDisconnected and StateInvalid are final states, after which
	// the endpoint is gone or doesn't exist, we should not increment metrics
	// for these states.
	if toState != "" && toState != StateDisconnected && toState != StateInvalid {
		metrics.EndpointStateCount.
			WithLabelValues(string(toState)).Inc()
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

// OnDNSPolicyUpdateLocked is called when the Endpoint's DNS policy has been updated
func (e *Endpoint) OnDNSPolicyUpdateLocked(rules restore.DNSRules) {
	e.DNSRules = rules
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
		e.getLogger().WithField(logfields.L4PolicyID, key).Debug("Proxy stats not found when updating")
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

// APICanModifyConfig determines whether API requests from users are allowed to
// modify the configuration of the endpoint.
func (e *Endpoint) APICanModifyConfig(n models.ConfigurationMap) error {
	if !e.OpLabels.OrchestrationIdentity.IsReserved() {
		return nil
	}
	for config, val := range n {
		if optionSetting, err := option.NormalizeBool(val); err == nil {
			if e.Options.Opts[config] == optionSetting {
				// The option won't be changed.
				continue
			}
			if config != option.Debug && config != option.DebugLB &&
				config != option.TraceNotify && config != option.PolicyVerdictNotify &&
				config != option.PolicyAuditMode && config != option.MonitorAggregation &&
				config != option.PolicyTracing {
				return fmt.Errorf("%s cannot be modified for endpoints with reserved labels", config)
			}
		}
	}
	return nil
}

// MetadataResolverCB provides an implementation for resolving the endpoint
// metadata for an endpoint such as the associated labels and annotations.
type MetadataResolverCB func(ns, podName string) (pod *slim_corev1.Pod, _ []slim_corev1.ContainerPort, identityLabels labels.Labels, infoLabels labels.Labels, annotations map[string]string, err error)

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
	const controllerPrefix = "resolve-labels"
	controllerName := fmt.Sprintf("%s-%s", controllerPrefix, e.GetK8sNamespaceAndPodName())
	go func() {
		select {
		case <-done:
		case <-e.aliveCtx.Done():
			return
		}
		e.controllers.RemoveController(controllerName)
	}()

	e.controllers.UpdateController(controllerName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				ns, podName := e.GetK8sNamespace(), e.GetK8sPodName()
				pod, cp, identityLabels, info, _, err := resolveMetadata(ns, podName)
				if err != nil {
					e.Logger(controllerPrefix).WithError(err).Warning("Unable to fetch kubernetes labels")
					return err
				}
				e.SetPod(pod)
				e.SetK8sMetadata(cp)
				e.UpdateNoTrackRules(func(_, _ string) (noTrackPort string, err error) {
					_, _, _, _, annotations, err := resolveMetadata(ns, podName)
					if err != nil {
						return "", err
					}
					return annotations[annotation.NoTrack], nil
				})
				e.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
					_, _, _, _, annotations, err := resolveMetadata(ns, podName)
					if err != nil {
						return "", err
					}
					return annotations[annotation.ProxyVisibility], nil
				})
				e.UpdateBandwidthPolicy(func(ns, podName string) (bandwidthEgress string, err error) {
					_, _, _, _, annotations, err := resolveMetadata(ns, podName)
					if err != nil {
						return "", err
					}
					return annotations[bandwidth.EgressBandwidth], nil
				})
				e.UpdateLabels(ctx, identityLabels, info, true)
				close(done)
				return nil
			},
			Context: e.aliveCtx,
		},
	)
}

// ModifyIdentityLabels changes the custom and orchestration identity labels of an endpoint.
// Labels can be added or deleted. If a label change is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(addLabels, delLabels labels.Labels) error {
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
		delete(idLabls, labels.IDNameInit)
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
	init, found := e.OpLabels.GetIdentityLabel(labels.IDNameInit)
	return found && init.Source == labels.LabelSourceReserved
}

// InitWithNodeLabels initializes the endpoint with the known node labels as
// well as reserved:host. It should only be used for the host endpoint.
func (e *Endpoint) InitWithNodeLabels(ctx context.Context, launchTime time.Duration) {
	if !e.IsHost() {
		return
	}

	epLabels := labels.Labels{}
	epLabels.MergeLabels(labels.LabelHost)

	// Initialize with known node labels.
	newLabels := labels.Map2Labels(node.GetLabels(), labels.LabelSourceK8s)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	epLabels.MergeLabels(newIdtyLabels)

	// Give the endpoint a security identity
	newCtx, cancel := context.WithTimeout(ctx, launchTime)
	defer cancel()
	e.UpdateLabels(newCtx, epLabels, epLabels, true)
	if errors.Is(newCtx.Err(), context.DeadlineExceeded) {
		log.WithError(newCtx.Err()).Warning("Timed out while updating security identify for host endpoint")
	}
}

// UpdateLabels is called to update the labels of an endpoint. Calls to this
// function do not necessarily mean that the labels actually changed. The
// container runtime layer will periodically synchronize labels.
//
// If a net label changed was performed, the endpoint will receive a new
// security identity and will be regenerated. Both of these operations will
// run first synchronously if 'blocking' is true, and then in the background.
//
// Returns 'true' if endpoint regeneration was triggered.
func (e *Endpoint) UpdateLabels(ctx context.Context, identityLabels, infoLabels labels.Labels, blocking bool) (regenTriggered bool) {
	log.WithFields(logrus.Fields{
		logfields.ContainerID:    e.GetShortContainerID(),
		logfields.EndpointID:     e.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	if err := e.lockAlive(); err != nil {
		e.logDisconnectedMutexAction(err, "when trying to refresh endpoint labels")
		return false
	}

	e.replaceInformationLabels(infoLabels)
	// replace identity labels and update the identity if labels have changed
	rev := e.replaceIdentityLabels(identityLabels)
	e.unlock()
	if rev != 0 {
		return e.runIdentityResolver(ctx, rev, blocking)
	}

	return false
}

// UpdateLabelsFrom is a convenience function to update an endpoint's identity
// labels from any source.
func (e *Endpoint) UpdateLabelsFrom(oldLbls, newLbls map[string]string, source string) error {
	newLabels := labels.Map2Labels(newLbls, source)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	oldLabels := labels.Map2Labels(oldLbls, source)
	oldIdtyLabels, _ := labelsfilter.Filter(oldLabels)

	err := e.ModifyIdentityLabels(newIdtyLabels, oldIdtyLabels)
	if err != nil {
		log.WithError(err).Debugf("Error while updating endpoint with new labels")
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: e.GetID(),
		logfields.Labels:     logfields.Repr(newIdtyLabels),
	}).Debug("Updated endpoint with new labels")
	return nil
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
// Must be called with e.mutex NOT held.
func (e *Endpoint) runIdentityResolver(ctx context.Context, myChangeRev int, blocking bool) (regenTriggered bool) {
	err := e.rlockAlive()
	if err != nil {
		// If a labels update and an endpoint delete API request arrive
		// in quick succession, this could occur; in that case, there's
		// no point updating the controller.
		e.getLogger().WithError(err).Info("Cannot run labels resolver")
		return false
	}
	newLabels := e.OpLabels.IdentityLabels()
	e.runlock()
	scopedLog := e.getLogger().WithField(logfields.IdentityLabels, newLabels)

	// If we are certain we can resolve the identity without accessing the KV
	// store, do it first synchronously right now. This can reduce the number
	// of regenerations for the endpoint during its initialization.
	regenTriggered = false
	if blocking || identity.IdentityAllocationIsLocal(newLabels) {
		scopedLog.Info("Resolving identity labels (blocking)")
		regenTriggered, err = e.identityLabelsChanged(ctx, myChangeRev)
		switch err {
		case ErrNotAlive:
			scopedLog.Debug("not changing endpoint identity because endpoint is in process of being removed")
			return false
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
				_, err := e.identityLabelsChanged(ctx, myChangeRev)
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

	return regenTriggered
}

func (e *Endpoint) identityLabelsChanged(ctx context.Context, myChangeRev int) (regenTriggered bool, err error) {
	// e.setState() called below, can't take a read lock.
	if err := e.lockAlive(); err != nil {
		return false, ErrNotAlive
	}
	newLabels := e.OpLabels.IdentityLabels()
	elog := e.getLogger().WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.IdentityLabels: newLabels,
	})

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.unlock()
		elog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return false, nil
	}

	if e.SecurityIdentity != nil && e.SecurityIdentity.Labels.Equals(newLabels) {
		// Sets endpoint state to ready if was waiting for identity
		if e.getState() == StateWaitingForIdentity {
			e.setState(StateReady, "Set identity for this endpoint")
		}
		e.unlock()
		elog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return false, nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.unlock()
	elog.Debug("Resolving identity for labels")

	allocateCtx, cancel := context.WithTimeout(ctx, option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	allocatedIdentity, _, err := e.allocator.AllocateIdentity(allocateCtx, newLabels, true)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %s", err)
		e.LogStatus(Other, Warning, fmt.Sprintf("%s (will retry)", err.Error()))
		return false, err
	}

	// When releasing identities after allocation due to either failure of
	// allocation or due a no longer used identity we want to operation to
	// continue even if the parent has given up. Enforce a timeout of two
	// minutes to avoid blocking forever but give plenty of time to release
	// the identity.
	releaseCtx, cancel := context.WithTimeout(ctx, option.Config.KVstoreConnectivityTimeout)
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
		return false, err
	}

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.unlock()

		releaseNewlyAllocatedIdentity()

		return false, nil
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
				return false, err
			}

			// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
			if e.identityResolutionIsObsolete(myChangeRev) {
				e.unlock()
				releaseNewlyAllocatedIdentity()
				return false, nil
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
	regenMetadata := &regeneration.ExternalRegenerationMetadata{
		Reason:            "updated security labels",
		RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
	}

	// Regeneration is only triggered once the endpoint ID has been
	// assigned. This ensures that on the initial creation, the endpoint is
	// not generated until the endpoint ID has been assigned. If the
	// identity is resolved before the endpoint ID is assigned, the
	// regeneration is deferred into endpointmanager.AddEndpoint(). If the
	// identity is not allocated yet when endpointmanager.AddEndpoint() is
	// called, the controller calling identityLabelsChanged() will trigger
	// the regeneration as soon as the identity is known.
	if e.ID != 0 {
		readyToRegenerate = e.setRegenerateStateLocked(regenMetadata)
	}

	// Unconditionally force policy recomputation after a new identity has been
	// assigned.
	e.forcePolicyComputation()

	// Trigger the sync-to-k8s-ciliumendpoint controller to sync the new
	// endpoint's identity.
	e.controllers.TriggerController(EndpointSyncControllerName(e.ID))

	e.unlock()

	if readyToRegenerate {
		e.Regenerate(regenMetadata)
	}

	return readyToRegenerate, nil
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

	return bpf.ObjPin(mapFd, e.BPFIpvlanMapPath())
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
// endpoint in the ep_config.h file.
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

// Delete cleans up all resources associated with this endpoint, including the
// following:
// * all goroutines managed by this Endpoint (EventQueue, Controllers)
// * removal from the endpointmanager, resulting in new events not taking effect
// on this endpoint
// * cleanup of datapath state (BPF maps, proxy configuration, directories)
// * releasing IP addresses allocated for the endpoint
// * releasing of the reference to its allocated security identity
func (e *Endpoint) Delete(conf DeleteConfig) []error {
	errs := []error{}

	e.Stop()

	// Lock out any other writers to the endpoint.  In case multiple delete
	// requests have been enqueued, have all of them except the first
	// return here. Ignore the request if the endpoint is already
	// disconnected.
	if err := e.lockAlive(); err != nil {
		return []error{}
	}
	e.setState(StateDisconnecting, "Deleting endpoint")

	// If dry mode is enabled, no changes to BPF maps are performed
	if !option.Config.DryMode {
		if errs2 := lxcmap.DeleteElement(e); errs2 != nil {
			errs = append(errs, errs2...)
		}

		if errs2 := e.deleteMaps(); errs2 != nil {
			errs = append(errs, errs2...)
		}
	}

	if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure || option.Config.IPAM == ipamOption.IPAMAlibabaCloud {
		e.getLogger().WithFields(logrus.Fields{
			"ep":     e.GetID(),
			"ipAddr": e.GetIPv4Address(),
		}).Debug("Deleting endpoint routing rules")

		// This is a best-effort attempt to cleanup. We expect there to be one
		// ingress rule and multiple egress rules. If we find more rules than
		// expected, then the rules will be left as-is because there was
		// likely manual intervention.
		if err := linuxrouting.Delete(e.IPv4.IP(), option.Config.EgressMultiHomeIPRuleCompat); err != nil {
			errs = append(errs, fmt.Errorf("unable to delete endpoint routing rules: %s", err))
		}
	}

	if e.noTrackPort > 0 {
		e.getLogger().WithFields(logrus.Fields{
			"ep":     e.GetID(),
			"ipAddr": e.GetIPv4Address(),
		}).Debug("Deleting endpoint NOTRACK rules")

		if e.IPv4.IsSet() {
			if err := iptables.RemoveNoTrackRules(e.IPv4.String(), e.noTrackPort, false); err != nil {
				errs = append(errs, fmt.Errorf("unable to delete endpoint NOTRACK ipv4 rules: %s", err))
			}
		}
		if e.IPv6.IsSet() {
			if err := iptables.RemoveNoTrackRules(e.IPv6.String(), e.noTrackPort, true); err != nil {
				errs = append(errs, fmt.Errorf("unable to delete endpoint NOTRACK ipv6 rules: %s", err))
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
	return e.GetID(), e.GetIPv4Address(), e.GetIPv6Address(), e.GetLabels(), e.GetLabelsSHA(), uint64(e.getIdentity()), err
}

// WaitForFirstRegeneration waits for specific conditions before returning:
// * if the endpoint has a sidecar proxy, it waits for the endpoint's BPF
// program to be generated for the first time.
// * otherwise, waits for the endpoint to complete its first full regeneration.
func (e *Endpoint) WaitForFirstRegeneration(ctx context.Context) error {
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

// GetCreatedAt returns the endpoint creation time.
func (e *Endpoint) GetCreatedAt() time.Time {
	return e.createdAt
}
