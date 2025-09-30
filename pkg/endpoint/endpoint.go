// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/monitor/notifications"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/types"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	maxLogs = 256

	resolveIdentity = "resolve-identity"
	resolveLabels   = "resolve-labels"
)

const (
	// PropertyFakeEndpoint marks the endpoint as being "fake". By "fake" it
	// means that it doesn't have any datapath bpf programs regenerated.
	PropertyFakeEndpoint = "property-fake-endpoint"

	// PropertyAtHostNS is used for endpoints that are reached via the host networking
	// namespace, but have their own IP(s) from the node's pod CIDR range
	PropertyAtHostNS = "property-at-host-network-namespace"

	// PropertyWithouteBPFDatapath marks the endpoint that doesn't contain a
	// eBPF datapath program.
	PropertyWithouteBPFDatapath = "property-without-bpf-endpoint"

	// PropertySkipBPFPolicy will mark the endpoint to skip ebpf
	// policy regeneration.
	PropertySkipBPFPolicy = "property-skip-bpf-policy"

	// PropertySkipBPFRegeneration will mark the endpoint to skip ebpf
	// regeneration.
	PropertySkipBPFRegeneration = "property-skip-bpf-regeneration"

	// PropertyCEPOwner will be able to store the CEP owner for this endpoint.
	PropertyCEPOwner = "property-cep-owner"

	// PropertyCEPName contains the CEP name for this endpoint.
	PropertyCEPName = "property-cep-name"
)

var (
	EndpointMutableOptionLibrary = option.GetEndpointMutableOptionLibrary()

	resolveIdentityControllerGroup = controller.NewGroup(resolveIdentity)

	resolveLabelsControllerGroup = controller.NewGroup(resolveLabels)
)

// State is an enumeration for possible endpoint states.
type State string

const (
	// StateWaitingForIdentity is used to set if the endpoint is waiting
	// for an identity from the KVStore.
	StateWaitingForIdentity = State(models.EndpointStateWaitingDashForDashIdentity)

	// StateReady specifies if the endpoint is ready to be used.
	StateReady = State(models.EndpointStateReady)

	// StateWaitingToRegenerate specifies when the endpoint needs to be regenerated, but regeneration has not started yet.
	StateWaitingToRegenerate = State(models.EndpointStateWaitingDashToDashRegenerate)

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
	dnsRulesAPI      DNSRulesAPI
	loader           datapath.Loader
	orchestrator     datapath.Orchestrator
	compilationLock  datapath.CompilationLock
	bandwidthManager datapath.BandwidthManager
	ipTablesManager  datapath.IptablesManager
	identityManager  identitymanager.IDManager
	monitorAgent     monitoragent.Agent
	wgConfig         wgTypes.WireguardConfig
	ipsecConfig      datapath.IPsecConfig

	epBuildQueue EndpointBuildQueue

	policyRepo policy.PolicyRepository

	// namedPortsGetter can get the ipcache.IPCache object.
	namedPortsGetter namedPortsGetter

	// kvstoreSyncher updates the kvstore (e.g., etcd) with up-to-date
	// information about endpoints. Initialized by manager.expose.
	kvstoreSyncher *ipcache.IPIdentitySynchronizer

	// ID of the endpoint, unique in the scope of the node
	ID uint16

	// createdAt stores the time the endpoint was created. This value is
	// recalculated on endpoint restore.
	createdAt time.Time

	initialEnvoyPolicyComputed chan struct{}

	// mutex protects write operations to this endpoint structure
	mutex lock.RWMutex

	// containerName is the name given to the endpoint by the container runtime.
	// It is not mutable once set, but is not set on the initial endpoint creation
	// when using the docker plugin. CNI-based clusters (read: all clusters) set
	// this on endpoint creation.
	containerName atomic.Pointer[string]

	// containerID is the container ID that docker has assigned to the endpoint.
	// It is not mutable once set, but is not set on the initial endpoint creation
	// when using the docker plugin. CNI-based clusters (read: all clusters) set
	// this on endpoint creation.
	containerID atomic.Pointer[string]

	// dockerNetworkID is the network ID of the libnetwork network if the
	// endpoint is a docker managed container which uses libnetwork
	// Constant after endpoint creation / restoration.
	dockerNetworkID string

	// dockerEndpointID is the Docker network endpoint ID if managed by
	// libnetwork.
	// immutable.
	dockerEndpointID string

	// ifName is the name of the host facing interface (veth pair) which
	// connects into the endpoint
	ifName string

	// ifIndex is the interface index of the host face interface (veth pair)
	ifIndex int

	// containerIfName is the name of the container facing interface (veth pair).
	// Immutable after Endpoint creation.
	containerIfName string

	// containerNetnsPath is the path to the container's network namespace.
	// Immutable after Endpoint creation.
	containerNetnsPath string

	// parentIfIndex is the interface index of the network device over which traffic
	// with the source endpoints IP should egress when that traffic is not masqueraded.
	parentIfIndex int

	// disableLegacyIdentifiers disables lookup using legacy endpoint identifiers
	// (container name, container id, pod name) for this endpoint.
	// Immutable after Endpoint creation.
	disableLegacyIdentifiers bool

	// labels is the endpoint's label configuration
	labels labels.OpLabels

	// identityRevision is incremented each time the identity label
	// information of the endpoint has changed
	identityRevision int

	// bps is the egress rate of the endpoint
	bps uint64

	// ingressBps is the ingress rate of the endpoint
	ingressBps uint64

	// mac is the MAC address of the endpoint
	// Constant after endpoint creation / restoration.
	mac mac.MAC // Container MAC address.

	IPv6Enabled bool

	// IPv6 is the IPv6 address of the endpoint.
	// Constant after endpoint creation / restoration.
	IPv6 netip.Addr

	// IPv6IPAMPool is the IPAM address pool from which the IPv6 address has been allocated from.
	// Constant after endpoint creation / restoration.
	IPv6IPAMPool string

	IPv4Enabled bool

	// IPv4 is the IPv4 address of the endpoint.
	// Constant after endpoint creation / restoration.
	IPv4 netip.Addr

	// IPv4IPAMPool is the IPAM address pool from which the IPv4 address has been allocated from.
	// Constant after endpoint creation / restoration.
	IPv4IPAMPool string

	// nodeMAC is the MAC of the node (agent). The MAC is different for every endpoint (veth),
	// or it may be all zeroes (netkit). Constant after endpoint creation / restoration.
	nodeMAC mac.MAC

	// SecurityIdentity is the security identity of this endpoint. This is computed from
	// the endpoint's labels.
	SecurityIdentity *identity.Identity `json:"SecLabel"`

	// policyMapFactory is used to create endpoint policy maps
	policyMapFactory policymap.Factory

	// policyMap is the policy related state of the datapath including
	// reference to all policy related BPF
	policyMap *policymap.PolicyMap

	// PolicyMapPressureUpdater updates the policymap pressure metric.
	PolicyMapPressureUpdater policyMapPressureUpdater

	// Options determine the datapath configuration of the endpoint.
	Options *option.IntOptions

	// status contains the last n state transitions this endpoint went through
	status *EndpointStatus

	// DNSRules is the collection of current endpoint-specific DNS proxy
	// rules that conform to using restore.PortProto V1 (that is, they do
	// **not** take protocol into account). These can be restored during
	// Cilium restart.
	// TODO: This can be removed when 1.16 is deprecated.
	DNSRules restore.DNSRules

	// DNSRulesV2 is the collection of current endpoint-specific DNS proxy
	// rules that conform to using restore.PortProto V2 (that is, they take
	// protocol into account). These can be restored during Cilium restart.
	DNSRulesV2 restore.DNSRules

	// DNSHistory is the collection of still-valid DNS responses intercepted for
	// this endpoint.
	DNSHistory *fqdn.DNSCache

	// DNSZombies is the collection of DNS IPs that have expired in or been
	// evicted from DNSHistory. They are held back from deletion until we can
	// confirm that no existing connection is using them.
	DNSZombies *fqdn.DNSZombieMappings

	// dnsHistoryTrigger is the trigger to write down the ep_config.h to make
	// sure that restores when DNS policy is in there are correct
	dnsHistoryTrigger atomic.Pointer[trigger.Trigger]

	// state is the state the endpoint is in. See setState()
	state State

	// bpfHeaderfileHash is the hash of the last BPF headerfile that has been
	// compiled and installed.
	bpfHeaderfileHash string

	// K8sPodName is the Kubernetes pod name of the endpoint.
	// Immutable after Endpoint creation.
	K8sPodName string

	// K8sNamespace is the Kubernetes namespace of the endpoint.
	// Immutable after Endpoint creation.
	K8sNamespace string

	// K8sUID is the Kubernetes UID of the pod. Passed directly from the CNI.
	// Immutable after Endpoint creation.
	K8sUID string

	// lockdown indicates whether the endpoint is locked down or not do to
	// a policy map overflow.
	lockdown bool

	// pod
	pod atomic.Pointer[slim_corev1.Pod]

	// k8sPorts contains container ports associated in the pod.
	// It is used to enforce k8s network policies with port names.
	k8sPorts atomic.Pointer[types.NamedPortMap]

	// logLimiter rate limits potentially repeating warning logs
	logLimiter logging.Limiter

	// policyRevision is the policy revision this endpoint is currently on
	// to modify this field please use endpoint.setPolicyRevision instead.
	//
	// To write, both ep.mutex and ep.buildMutex must be held.
	policyRevision uint64

	// policyRevisionSignals contains a map of PolicyRevision signals that
	// should be triggered once the policyRevision reaches the wanted wantedRev.
	policyRevisionSignals map[*policySignal]bool

	// proxyPolicyRevision is the policy revision that has been applied to
	// the proxy.
	proxyPolicyRevision uint64

	// proxyStatisticsMutex is the mutex that must be held to read or write
	// proxyStatistics.
	// No other locks may be taken while holding proxyStatisticsMutex.
	proxyStatisticsMutex lock.RWMutex

	proxy EndpointProxy

	// proxyStatistics contains statistics of proxy redirects.
	// They keys in this map are policy.ProxyIDs.
	// You must hold Endpoint.proxyStatisticsMutex to read or write it.
	proxyStatistics map[string]*models.ProxyStatistics

	// nextPolicyRevision is the policy revision that the endpoint has
	// updated to and that will become effective with the next regenerate.
	// Must hold the endpoint mutex *and* buildMutex to write, and either to read.
	nextPolicyRevision uint64

	// forcePolicyCompute full endpoint policy recomputation
	// Set when endpoint options have been changed. Cleared right before releasing the
	// endpoint mutex after policy recalculation.
	forcePolicyCompute bool

	// buildMutex synchronizes builds of individual endpoints and locks out
	// deletion during builds
	buildMutex lock.Mutex

	// loggerAttrs are attributes.
	loggerAttrs lock.Map[string, any]

	// loggerAttrs are attributes.
	policyLoggerAttrs lock.Map[string, any]

	// logger is a logrus object with fields set to report an endpoints information.
	// This must only be accessed with atomic.LoadPointer/StorePointer.
	// 'mutex' must be Lock()ed to synchronize stores. No lock needs to be held
	// when loading this pointer.
	logger atomic.Pointer[slog.Logger]

	// logger is a logrus object with fields set to report an endpoints information.
	// This must only be accessed with atomic.LoadPointer/StorePointer.
	// 'mutex' must be Lock()ed to synchronize stores. No lock needs to be held
	// when loading this pointer.
	loggerNoSubsys atomic.Pointer[slog.Logger]

	basePolicyLogger atomic.Pointer[slog.Logger]

	// Points to a shared policy debug log file.
	policyDebugLog io.Writer

	// policyLogger is a logrus object with fields set to report an endpoints information.
	// This must only be accessed with atomic LoadPointer/StorePointer.
	// 'mutex' must be Lock()ed to synchronize stores. No lock needs to be held
	// when loading this pointer.
	policyLogger atomic.Pointer[slog.Logger]

	// controllers is the list of async controllers syncing the endpoint to
	// other resources
	controllers *controller.Manager

	// ctCleaned indicates whether the conntrack table has already been
	// cleaned when this endpoint was first created
	ctCleaned bool

	hasBPFProgram chan struct{}

	// desiredPolicy is the policy calculated during regeneration. After
	// successful regeneration, it is copied to realizedPolicy
	// To write, both ep.mutex and ep.buildMutex must be held.
	desiredPolicy *policy.EndpointPolicy

	// realizedPolicy is the policy that has most recently been applied.
	// ep.mutex must be held.
	realizedPolicy *policy.EndpointPolicy

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

	isIngress bool
	isHost    bool

	noTrackPort uint16

	// mutable! must hold the endpoint lock to read
	ciliumEndpointUID k8sTypes.UID

	// properties is used to store some internal properties about this Endpoint.
	properties map[string]any

	// Root scope for all of this endpoints reporters.
	reporterScope       cell.Health
	closeHealthReporter func()

	// NetNsCookie is the network namespace cookie of the Endpoint.
	NetNsCookie uint64

	ctMapGC ctmap.GCRunner
}

// GetPolicyNames returns the policy names for this endpoint.
// For Endpoint, the policy names are the IP addresses of the endpoint.
func (e *Endpoint) GetPolicyNames() []string {
	var ips []string
	if ipv6 := e.GetIPv6Address(); ipv6 != "" {
		ips = append(ips, ipv6)
	}
	if ipv4 := e.GetIPv4Address(); ipv4 != "" {
		ips = append(ips, ipv4)
	}
	return ips
}

func (e *Endpoint) GetReporter(name string) cell.Health {
	if e.reporterScope == nil {
		_, h := cell.NewSimpleHealth()
		return h.NewScope(name)
	}
	return e.reporterScope.NewScope(name)
}

func (e *Endpoint) InitEndpointHealth(parent cell.Health) {
	if parent == nil {
		_, parent = cell.NewSimpleHealth()
	}
	s := parent.NewScope(fmt.Sprintf("cilium-endpoint-%d (%s)", e.ID, e.GetK8sNamespaceAndPodName()))
	if s != nil {
		e.closeHealthReporter = s.Close
		e.reporterScope = s
	}
}

func (e *Endpoint) Close() {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.closeHealthReporter != nil {
		e.closeHealthReporter()
	}

	if e.PolicyMapPressureUpdater != nil {
		e.PolicyMapPressureUpdater.Remove(e.ID)
	}
}

type namedPortsGetter interface {
	GetNamedPorts() (npm types.NamedPortMultiMap)
}

type DNSRulesAPI interface {
	// GetDNSRules creates a fresh copy of DNS rules that can be used when
	// endpoint is restored on a restart.
	// The endpoint lock must not be held while calling this function.
	GetDNSRules(epID uint16) restore.DNSRules

	// RemoveRestoredDNSRules removes any restored DNS rules for
	// this endpoint from the DNS proxy.
	RemoveRestoredDNSRules(epID uint16)
}

// EndpointSyncControllerName returns the controller name to synchronize
// endpoint in to kubernetes.
func EndpointSyncControllerName(epID uint16) string {
	return "sync-to-k8s-ciliumendpoint (" + strconv.FormatUint(uint64(epID), 10) + ")"
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

// GetParentIfIndex returns the parentIfIndex for this endpoint.
func (e *Endpoint) GetParentIfIndex() int {
	return e.parentIfIndex
}

// LXCMac returns the LXCMac for this endpoint.
func (e *Endpoint) LXCMac() mac.MAC {
	return e.mac
}

func (e *Endpoint) IsAtHostNS() bool {
	return e.isProperty(PropertyAtHostNS)
}

func (e *Endpoint) IsHost() bool {
	return e.isHost
}

// SetIsHost is a convenient method to create host endpoints for testing.
func (ep *Endpoint) SetIsHost(isHost bool) {
	ep.isHost = isHost
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

// waitForProxyCompletions blocks until all proxy changes have been completed.
// Called with buildMutex held.
func (e *Endpoint) waitForProxyCompletions(proxyWaitGroup *completion.WaitGroup) error {
	if proxyWaitGroup == nil {
		return nil
	}

	err := proxyWaitGroup.Context().Err()
	if err != nil {
		return fmt.Errorf("context cancelled before waiting for proxy updates: %w", err)
	}

	start := time.Now()

	e.getLogger().Debug("Waiting for proxy updates to complete...")
	err = proxyWaitGroup.Wait()
	if err != nil {
		return fmt.Errorf("proxy state changes failed: %w", err)
	}
	e.getLogger().Debug("Wait time for proxy updates", logfields.Duration, time.Since(start))

	return nil
}

func createEndpoint(logger *slog.Logger, dnsRulesAPI DNSRulesAPI, epBuildQueue EndpointBuildQueue, loader datapath.Loader, orchestrator datapath.Orchestrator, compilationLock datapath.CompilationLock, bandwidthManager datapath.BandwidthManager, ipTablesManager datapath.IptablesManager, identityManager identitymanager.IDManager, monitorAgent monitoragent.Agent, policyMapFactory policymap.Factory, policyRepo policy.PolicyRepository, namedPortsGetter namedPortsGetter, proxy EndpointProxy, allocator cache.IdentityAllocator, ctMapGC ctmap.GCRunner, kvstoreSyncher *ipcache.IPIdentitySynchronizer, ID uint16, ifName string, wgCfg wgTypes.WireguardConfig, ipsecCfg datapath.IPsecConfig, policyDebugLog io.Writer) *Endpoint {
	ep := &Endpoint{
		dnsRulesAPI:        dnsRulesAPI,
		epBuildQueue:       epBuildQueue,
		loader:             loader,
		orchestrator:       orchestrator,
		compilationLock:    compilationLock,
		bandwidthManager:   bandwidthManager,
		ipTablesManager:    ipTablesManager,
		identityManager:    identityManager,
		monitorAgent:       monitorAgent,
		wgConfig:           wgCfg,
		ipsecConfig:        ipsecCfg,
		policyMapFactory:   policyMapFactory,
		policyRepo:         policyRepo,
		namedPortsGetter:   namedPortsGetter,
		ID:                 ID,
		createdAt:          time.Now(),
		proxy:              proxy,
		ifName:             ifName,
		labels:             labels.NewOpLabels(),
		Options:            option.NewIntOptions(&EndpointMutableOptionLibrary),
		DNSRules:           nil,
		DNSRulesV2:         nil,
		DNSHistory:         fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		DNSZombies:         fqdn.NewDNSZombieMappings(logger, option.Config.ToFQDNsMaxDeferredConnectionDeletes, option.Config.ToFQDNsMaxIPsPerHost),
		state:              "",
		status:             NewEndpointStatus(),
		hasBPFProgram:      make(chan struct{}),
		desiredPolicy:      policy.NewEndpointPolicy(logger, policyRepo),
		controllers:        controller.NewManager(),
		regenFailedChan:    make(chan struct{}, 1),
		allocator:          allocator,
		logLimiter:         logging.NewLimiter(10*time.Second, 3), // 1 log / 10 secs, burst of 3
		noTrackPort:        0,
		properties:         map[string]any{},
		ctMapGC:            ctMapGC,
		kvstoreSyncher:     kvstoreSyncher,
		policyDebugLog:     policyDebugLog,
		forcePolicyCompute: true,
	}

	ep.initialEnvoyPolicyComputed = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	ep.aliveCancel = cancel
	ep.aliveCtx = ctx

	ep.realizedPolicy = ep.desiredPolicy

	ep.SetDefaultOpts(option.Config.Opts)

	return ep
}

func (e *Endpoint) initDNSHistoryTrigger() {
	if e.dnsHistoryTrigger.Load() != nil {
		// Already initialized, bail out.
		return
	}

	// Note: This can only fail if the trigger func is nil.
	trigger, err := trigger.NewTrigger(trigger.Parameters{
		Name:        "sync_endpoint_header_file",
		MinInterval: 5 * time.Second,
		TriggerFunc: e.syncEndpointHeaderFile,
		ShutdownFunc: func() {
			e.syncEndpointHeaderFile([]string{"Sync Endpoint DNS State on Shutdown"})
		},
	})
	if err != nil {
		e.getLogger().Error(
			"Failed to create the endpoint header file sync trigger",
			logfields.Error, err,
		)
		return
	}
	e.dnsHistoryTrigger.Store(trigger)
}

// CreateIngressEndpoint creates the endpoint corresponding to Cilium Ingress.
func CreateIngressEndpoint(logger *slog.Logger, dnsRulesAPI DNSRulesAPI, epBuildQueue EndpointBuildQueue, loader datapath.Loader, orchestrator datapath.Orchestrator, compilationLock datapath.CompilationLock, bandwidthManager datapath.BandwidthManager, ipTablesManager datapath.IptablesManager, identityManager identitymanager.IDManager, monitorAgent monitoragent.Agent, policyMapFactory policymap.Factory, policyRepo policy.PolicyRepository, namedPortsGetter namedPortsGetter, proxy EndpointProxy, allocator cache.IdentityAllocator, ctMapGC ctmap.GCRunner, kvstoreSyncher *ipcache.IPIdentitySynchronizer, wgCfg wgTypes.WireguardConfig, ipsecCfg datapath.IPsecConfig, policyDebugLog io.Writer) (*Endpoint, error) {
	ep := createEndpoint(logger, dnsRulesAPI, epBuildQueue, loader, orchestrator, compilationLock, bandwidthManager, ipTablesManager, identityManager, monitorAgent, policyMapFactory, policyRepo, namedPortsGetter, proxy, allocator, ctMapGC, kvstoreSyncher, 0, "", wgCfg, ipsecCfg, policyDebugLog)
	ep.DatapathConfiguration = NewDatapathConfiguration()

	ep.isIngress = true

	// An ingress endpoint is defined without a veth interface and no bpf
	// programs or maps are created for it. Thus, we will set its properties
	// to not have a bpf policy map nor a bpf datapath.

	// Ingress endpoint is reachable via the host networking namespace
	// Host delivery flag is set in lxcmap
	ep.properties[PropertyAtHostNS] = true

	// Ingress endpoint has no bpf policy maps
	ep.properties[PropertySkipBPFPolicy] = true

	// Ingress endpoint has no bpf programs
	ep.properties[PropertyWithouteBPFDatapath] = true

	// node.GetIngressIPv4 has been parsed with net.ParseIP() and may be in IPv4 mapped IPv6
	// address format. Use netipx.FromStdIP() to make sure we get a plain IPv4 address.
	ep.IPv4, _ = netipx.FromStdIP(node.GetIngressIPv4(logger))
	ep.IPv6, _ = netip.AddrFromSlice(node.GetIngressIPv6(logger))

	ep.setState(StateWaitingForIdentity, "Ingress Endpoint creation")

	return ep, nil
}

// CreateHostEndpoint creates the endpoint corresponding to the host.
func CreateHostEndpoint(logger *slog.Logger, dnsRulesAPI DNSRulesAPI, epBuildQueue EndpointBuildQueue, loader datapath.Loader, orchestrator datapath.Orchestrator, compilationLock datapath.CompilationLock, bandwidthManager datapath.BandwidthManager, ipTablesManager datapath.IptablesManager, identityManager identitymanager.IDManager, monitorAgent monitoragent.Agent, policyMapFactory policymap.Factory, policyRepo policy.PolicyRepository, namedPortsGetter namedPortsGetter, proxy EndpointProxy, allocator cache.IdentityAllocator, ctMapGC ctmap.GCRunner, kvstoreSyncher *ipcache.IPIdentitySynchronizer, wgCfg wgTypes.WireguardConfig, ipsecCfg datapath.IPsecConfig, policyDebugLog io.Writer) (*Endpoint, error) {
	iface, err := safenetlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return nil, err
	}

	ep := createEndpoint(logger, dnsRulesAPI, epBuildQueue, loader, orchestrator, compilationLock, bandwidthManager, ipTablesManager, identityManager, monitorAgent, policyMapFactory, policyRepo, namedPortsGetter, proxy, allocator, ctMapGC, kvstoreSyncher, 0, defaults.HostDevice, wgCfg, ipsecCfg, policyDebugLog)
	ep.isHost = true
	ep.mac = mac.MAC(iface.Attrs().HardwareAddr)
	ep.nodeMAC = mac.MAC(iface.Attrs().HardwareAddr)
	ep.ifIndex = iface.Attrs().Index
	ep.DatapathConfiguration = NewDatapathConfiguration()

	ep.setState(StateWaitingForIdentity, "Endpoint creation")

	return ep, nil
}

// GetID returns the endpoint's ID as a 64-bit unsigned integer.
func (e *Endpoint) GetID() uint64 {
	return uint64(e.ID)
}

// GetLabels returns the labels.
func (e *Endpoint) GetLabels() labels.Labels {
	if err := e.rlockAlive(); err != nil {
		return nil
	}
	defer e.runlock()
	if e.SecurityIdentity == nil {
		return labels.Labels{}
	}

	return e.SecurityIdentity.Labels
}

// GetSecurityIdentity returns the security identity of the endpoint.
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
	return e.ifName
}

// GetOpLabels returns the labels as slice
func (e *Endpoint) GetOpLabels() []string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.labels.IdentityLabels().GetModel()
}

// GetOptions returns the datapath configuration options of the endpoint.
func (e *Endpoint) GetOptions() *option.IntOptions {
	return e.Options
}

// GetIPv4Address returns the IPv4 address of the endpoint as a string
func (e *Endpoint) GetIPv4Address() string {
	if !e.IPv4.IsValid() {
		return ""
	}
	// e.IPv4 is assumed to not be an IPv4 mapped IPv6 address, which would be
	// formatted like "::ffff:1.2.3.4"
	return e.IPv4.String()
}

// GetIPv6Address returns the IPv6 address of the endpoint as a string
func (e *Endpoint) GetIPv6Address() string {
	if !e.IPv6.IsValid() {
		return ""
	}
	return e.IPv6.String()
}

// IPv4Address returns the IPv4 address of the endpoint
func (e *Endpoint) IPv4Address() netip.Addr {
	return e.IPv4
}

// IPv6Address returns the IPv6 address of the endpoint
func (e *Endpoint) IPv6Address() netip.Addr {
	return e.IPv6
}

// GetNodeMAC returns the MAC address of the node from this endpoint's perspective.
func (e *Endpoint) GetNodeMAC() mac.MAC {
	return e.nodeMAC
}

// StringID returns the endpoint's ID in a string.
func (e *Endpoint) StringID() string {
	return strconv.Itoa(int(e.ID))
}

// GetIdentity returns the numeric security identity of the endpoint
func (e *Endpoint) GetIdentity() identity.NumericIdentity {
	e.unconditionalRLock()
	defer e.runlock()

	return e.getIdentity()
}

// GetEndpointNetNsCookie returns the endpoint's netns cookie.
func (e *Endpoint) GetEndpointNetNsCookie() uint64 {
	return e.NetNsCookie
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

	keyToLookup := policy.IngressKey().WithIdentity(id)

	v, ok := e.desiredPolicy.Get(keyToLookup)
	return ok && !v.IsDeny()
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
func optionChanged(key string, value option.OptionSetting, data any) {
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

// SetDefaultOpts configures all options for the endpoint, getting the values from 'opts'.
func (e *Endpoint) SetDefaultOpts(opts *option.IntOptions) {
	if opts != nil {
		for k := range EndpointMutableOptionLibrary {
			e.Options.SetValidated(k, opts.GetValue(k))
		}
	}
	e.UpdateLogger(nil)
}

// base64 returns the endpoint in a base64 format.
func (e *Endpoint) base64() (string, error) {
	jsonBytes, err := e.MarshalJSON()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
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

// ParseEndpoint parses the JSON representation of an endpoint.
//
// Note that the parse'd endpoint's identity is only partially restored. The
// caller must call `SetIdentity()` to make the returned endpoint's identity useful.
func ParseEndpoint(logger *slog.Logger, dnsRulesAPI DNSRulesAPI, epBuildQueue EndpointBuildQueue, loader datapath.Loader, orchestrator datapath.Orchestrator, compilationLock datapath.CompilationLock, bandwidthManager datapath.BandwidthManager, ipTablesManager datapath.IptablesManager, identityManager identitymanager.IDManager, monitorAgent monitoragent.Agent, policyMapFactory policymap.Factory, policyRepo policy.PolicyRepository, namedPortsGetter namedPortsGetter, proxy EndpointProxy, allocator cache.IdentityAllocator, ctMapGC ctmap.GCRunner, kvstoreSyncher *ipcache.IPIdentitySynchronizer, epJSON []byte, wgCfg wgTypes.WireguardConfig, ipsecCfg datapath.IPsecConfig) (*Endpoint, error) {
	ep := Endpoint{
		dnsRulesAPI:      dnsRulesAPI,
		epBuildQueue:     epBuildQueue,
		loader:           loader,
		orchestrator:     orchestrator,
		compilationLock:  compilationLock,
		bandwidthManager: bandwidthManager,
		ipTablesManager:  ipTablesManager,
		identityManager:  identityManager,
		monitorAgent:     monitorAgent,
		wgConfig:         wgCfg,
		ipsecConfig:      ipsecCfg,
		policyMapFactory: policyMapFactory,
		namedPortsGetter: namedPortsGetter,
		policyRepo:       policyRepo,
		proxy:            proxy,
		allocator:        allocator,
		ctMapGC:          ctMapGC,
		kvstoreSyncher:   kvstoreSyncher,
	}

	if err := ep.UnmarshalJSON(epJSON); err != nil {
		return nil, fmt.Errorf("failed to parse restored endpoint: %w", err)
	}

	// Set default options, unsupported options were already dropped by
	// ep.Options.UnmarshalJSON
	ep.SetDefaultOpts(nil)

	// Initialize fields to values which are non-nil that are not serialized.
	ep.hasBPFProgram = make(chan struct{})
	ep.desiredPolicy = policy.NewEndpointPolicy(logger, policyRepo)
	ep.realizedPolicy = ep.desiredPolicy
	ep.forcePolicyCompute = true
	ep.controllers = controller.NewManager()
	ep.regenFailedChan = make(chan struct{}, 1)

	ep.aliveCtx, ep.aliveCancel = context.WithCancel(context.Background())

	// If host label is present, it's the host endpoint.
	ep.isHost = ep.HasLabels(labels.LabelHost)
	// If Ingress label is present, it's the Ingress endpoint.
	ep.isIngress = ep.HasLabels(labels.LabelIngress)

	if ep.isHost || ep.isIngress {
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

	e.getLogger().Debug(
		msg,
		logfields.Code, sts.Status.Code,
		logfields.Type, sts.Status.Type,
		logfields.EndpointState, sts.Status.State,
		logfields.PolicyRevision, e.policyRevision,
	)
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

	e.getLogger().Debug("updating endpoint configuration options", logfields.Config, cfg)

	// CurrentStatus will be not OK when we have an uncleared error in BPF,
	// policy or Other. We should keep trying to regenerate in the hopes of
	// succeeding.
	// Note: This "retry" behaviour is better suited to a controller, and can be
	// moved there once we have an endpoint regeneration controller.
	regenCtx := &regeneration.ExternalRegenerationMetadata{
		Reason:            "endpoint was updated via API",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
	}

	// Only regenerate if necessary.
	if cfg.Options == nil || e.updateAndOverrideEndpointOptions(om) || e.status.CurrentStatus() != OK {
		regenCtx.RegenerationLevel = regeneration.RegenerateWithDatapath

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
				e.getLogger().Warn(
					"timed out waiting for endpoint state to change",
				)
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
	allEpLabels := e.labels.AllLabels()

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

// replaceInformationLabels replaces the information labels of the endpoint that
// match the respective 'sourceFilter', if 'sourceFilter' is 'LabelSourceAny'
// then all labels are replaced.
// Passing a nil set of labels will not perform any action.
// Must be called with e.mutex.Lock().
func (e *Endpoint) replaceInformationLabels(sourceFilter string, l labels.Labels) {
	if l == nil {
		return
	}
	e.labels.ReplaceInformationLabels(sourceFilter, l, e.getLogger())
}

// replaceIdentityLabels replaces the identity labels of the endpoint for the
// given 'sourceFilter', if 'sourceFilter' is 'LabelSourceAny' then all labels
// are replaced.
// If a net changed occurred, the identityRevision is bumped and returned,
// otherwise 0 is returned.
// Passing a nil set of labels will not perform any action and will return the
// current endpoint's identityRevision.
// Must be called with e.mutex.Lock().
func (e *Endpoint) replaceIdentityLabels(sourceFilter string, l labels.Labels) int {
	if l == nil {
		return e.identityRevision
	}

	changed := e.labels.ReplaceIdentityLabels(sourceFilter, l, e.getLogger())
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
func (e *Endpoint) leaveLocked(conf DeleteConfig) []error {
	errs := []error{}

	// Remove policy references from shared policy structures
	// Endpoint with desiredPolicy computed can get deleted while queueing for regeneration,
	// must mark the policy as 'Ready' so that Detach does not complain about it.
	e.desiredPolicy.Ready()
	e.desiredPolicy.Detach(e.getLogger())
	// Passing a new map of nil will purge all redirects
	e.removeOldRedirects(nil, e.desiredPolicy.Redirects)

	if e.realizedPolicy != e.desiredPolicy {
		e.realizedPolicy.Detach(e.getLogger())
		// Passing a new map of nil will purge all redirects
		e.removeOldRedirects(nil, e.realizedPolicy.Redirects)
	}

	// Remove restored rules of cleaned endpoint
	e.dnsRulesAPI.RemoveRestoredDNSRules(e.ID)

	if e.policyMap != nil {
		if err := e.policyMap.Close(); err != nil {
			errs = append(errs, fmt.Errorf("unable to close policymap %s: %w", e.policyMap.String(), err))
		}
	}

	if !conf.NoIdentityRelease && e.SecurityIdentity != nil {
		// Restored endpoint may be created with a reserved identity of 5
		// (init), which is not registered in the identity manager and
		// therefore doesn't need to be removed.
		if e.SecurityIdentity.ID != identity.ReservedIdentityInit {
			e.identityManager.Remove(e.SecurityIdentity)
		}

		_, err := e.allocator.Release(context.Background(), e.SecurityIdentity, false)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to release identity: %w", err))
		}
		e.removeNetworkPolicy()
		e.SecurityIdentity = nil
	}

	e.removeDirectories()
	e.controllers.RemoveAll()
	e.cleanPolicySignals()

	if !e.isProperty(PropertyFakeEndpoint) {
		e.scrubIPsInConntrackTableLocked()
	}

	e.setState(StateDisconnected, "Endpoint removed")

	endpointPolicyStatus.Remove(e.ID)
	e.getLogger().Info("Removed endpoint")

	return errs
}

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	// const after creation
	ns := e.K8sNamespace
	return ns
}

// GetK8sUID returns the UID of the pod if the endpoint represents a Kubernetes
// pod.
func (e *Endpoint) GetK8sUID() string {
	// const after creation
	uid := e.K8sUID
	return uid
}

// SetPod sets the pod related to this endpoint.
func (e *Endpoint) SetPod(pod *slim_corev1.Pod) {
	e.pod.Store(pod)
}

// GetPod retrieves the pod related to this endpoint
func (e *Endpoint) GetPod() *slim_corev1.Pod {
	return e.pod.Load()
}

// CEPOwnerInterface contains the interface of an endpoint owner.
type CEPOwnerInterface interface {
	// IsNil returns true or false if the object is nil.
	IsNil() bool

	// GetAPIVersion returns the API version of the owner.
	GetAPIVersion() string

	// GetKind returns the Kind of the owner.
	GetKind() string

	// GetNamespace returns the namespace where the owner lives.
	GetNamespace() string

	// GetName returns the owners' name.
	GetName() string

	// GetLabels returns the labels of the owner.
	GetLabels() map[string]string

	// GetUID returns the owners' UID.
	GetUID() k8sTypes.UID

	// GetHostIP returns the owners' host IP.
	GetHostIP() string
}

// GetCEPOwner retrieves the cep owner related to this endpoint which will be,
// by default, the pod associated with this endpoint.
func (e *Endpoint) GetCEPOwner() CEPOwnerInterface {
	if cepOwnerInt, ok := e.properties[PropertyCEPOwner]; ok {
		cepOwner, ok := cepOwnerInt.(CEPOwnerInterface)
		if ok {
			return cepOwner
		}
	}

	return e.GetPod()
}

// SetK8sMetadata sets the k8s container ports specified by kubernetes.
// Note that once put in place, the new k8sPorts is never changed,
// so that the map can be used concurrently without keeping locks.
// Can't really error out as that might break backwards compatibility.
func (e *Endpoint) SetK8sMetadata(containerPorts []slim_corev1.ContainerPort) {
	k8sPorts := make(types.NamedPortMap, len(containerPorts))
	for _, cp := range containerPorts {
		if cp.Name == "" {
			continue // silently skip unnamed ports
		}
		err := k8sPorts.AddPort(cp.Name, int(cp.ContainerPort), string(cp.Protocol))
		if err != nil {
			e.getLogger().Warn("Adding named port failed", logfields.Error, err)
			continue
		}
	}
	e.k8sPorts.Store(&k8sPorts)
}

// GetK8sPorts returns the k8sPorts, which must not be modified by the caller
func (e *Endpoint) GetK8sPorts() (k8sPorts types.NamedPortMap) {
	if p := e.k8sPorts.Load(); p != nil {
		k8sPorts = *p
	}
	return k8sPorts
}

// HaveK8sMetadata returns true once hasK8sMetadata was set
func (e *Endpoint) HaveK8sMetadata() (metadataSet bool) {
	p := e.k8sPorts.Load()
	return p != nil
}

// K8sNamespaceAndPodNameIsSet returns true if the namespace and the pod name
// are both set.
func (e *Endpoint) K8sNamespaceAndPodNameIsSet() bool {
	e.unconditionalLock()
	defer e.unlock()
	return e.K8sNamespace != "" && e.K8sPodName != ""
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

// SetMac modifies the endpoint's mac.
func (e *Endpoint) SetMac(mac mac.MAC) {
	e.unconditionalLock()
	defer e.unlock()
	e.mac = mac
}

// GetDisableLegacyIdentifiers returns the endpoint's disableLegacyIdentifiers.
func (e *Endpoint) GetDisableLegacyIdentifiers() bool {
	e.unconditionalRLock()
	defer e.runlock()
	return e.disableLegacyIdentifiers
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
		e.getLogger().Info(
			"Invalid state transition skipped",
			logfields.EndpointStateFrom, fromState,
			logfields.EndpointStateTo, toState,
			logfields.File, fileName,
			logfields.Line, fileLine,
		)
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

func (e *Endpoint) GetPolicyVersionHandle() *versioned.VersionHandle {
	if e.desiredPolicy != nil {
		return e.desiredPolicy.VersionHandle
	}
	return nil
}

func (e *Endpoint) GetListenerProxyPort(listener string) uint16 {
	return e.proxy.GetListenerProxyPort(listener)
}

// getProxyStatistics gets the ProxyStatistics for the flows with the
// given characteristics, or adds a new one and returns it.
func (e *Endpoint) getProxyStatistics(key string, l7Protocol string, port uint16, ingress bool, redirectPort uint16) *models.ProxyStatistics {
	e.proxyStatisticsMutex.Lock()
	defer e.proxyStatisticsMutex.Unlock()

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

	proxyStats.AllocatedProxyPort = int64(redirectPort)

	return proxyStats
}

// UpdateProxyStatistics updates the Endpoint's proxy  statistics to account
// for a new observed flow with the given characteristics.
func (e *Endpoint) UpdateProxyStatistics(proxyType, l4Protocol string, port, proxyPort uint16, ingress, request bool, verdict accesslog.FlowVerdict) {
	key := policy.ProxyStatsKey(ingress, l4Protocol, port, proxyPort)

	e.proxyStatisticsMutex.Lock()
	defer e.proxyStatisticsMutex.Unlock()

	proxyStats, ok := e.proxyStatistics[key]
	if !ok {
		e.getLogger().Debug(
			"Proxy stats not found when updating",
			logfields.L4PolicyID, key,
		)

		return
	}

	var stats *models.MessageForwardingStatistics
	if request {
		stats = proxyStats.Statistics.Requests
	} else {
		stats = proxyStats.Statistics.Responses
	}

	stats.Received++
	metrics.ProxyPolicyL7Total.WithLabelValues("received", proxyType).Inc()

	switch verdict {
	case accesslog.VerdictForwarded:
		stats.Forwarded++
		metrics.ProxyPolicyL7Total.WithLabelValues("forwarded", proxyType).Inc()
	case accesslog.VerdictDenied:
		stats.Denied++
		metrics.ProxyPolicyL7Total.WithLabelValues("denied", proxyType).Inc()
	case accesslog.VerdictError:
		stats.Error++
		metrics.ProxyPolicyL7Total.WithLabelValues("parse_errors", proxyType).Inc()
	}
}

// APICanModify determines whether API requests from a user are allowed to
// modify this endpoint.
func APICanModify(e *Endpoint) error {
	if e.IsInit() {
		return nil
	}
	if e.labels.OrchestrationIdentity.IsReserved() {
		return fmt.Errorf("endpoint may not be associated reserved labels")
	}
	return nil
}

// APICanModifyConfig determines whether API requests from users are allowed to
// modify the configuration of the endpoint.
func (e *Endpoint) APICanModifyConfig(n models.ConfigurationMap) error {
	if !e.labels.OrchestrationIdentity.IsReserved() {
		return nil
	}
	for config, val := range n {
		if optionSetting, err := option.NormalizeBool(val); err == nil {
			if e.Options.GetValue(config) == optionSetting {
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

// metadataResolver will resolve the endpoint's metadata from a metadata
// resolver.
//
//   - restoredEndpoint - should be set to 'true' if the endpoint is being
//     restored.
//
//   - blocking - will block this function until the endpoint receives a new
//     security identity, and it is regenerated. If 'false', this
//     operation will be done in the background and 'regenTriggered'
//     will always be 'false'.
//
//   - bwm - the bandwidth manager used to update the bandwidth policy for this
//     endpoint.
//
//   - resolveMetadata - the metadata resolver that will be used to retrieve this
//     endpoint's metadata.
func (e *Endpoint) metadataResolver(ctx context.Context,
	restoredEndpoint, blocking bool,
	baseLabels labels.Labels,
	resolveMetadata MetadataResolverCB,
) (regenTriggered bool, err error) {
	if !e.K8sNamespaceAndPodNameIsSet() {
		e.Logger(resolveLabels).Debug("Namespace and Pod are not set")
		return false, nil
	}

	// copy the base labels into this local variable
	// so that we don't override 'baseLabels'.
	controllerBaseLabels := labels.NewFrom(baseLabels)

	ns, podName := e.GetK8sNamespace(), e.GetK8sPodName()

	pod, k8sMetadata, err := resolveMetadata(ns, podName, e.K8sUID)
	if err != nil {
		if restoredEndpoint && k8sErrors.IsNotFound(err) {
			e.Logger(resolveLabels).Info(
				"Unable to resolve metadata during endpoint restoration. Is the pod still running?",
				logfields.Error, err,
			)
		} else {
			e.Logger(resolveLabels).Warn(
				"Unable to fetch kubernetes labels",
				logfields.Error, err,
			)
		}

		// If we were unable to fetch the k8s endpoints then
		// we will mark the endpoint with the init identity.
		if !restoredEndpoint {
			// Only mark the endpoint with the 'init' identity if we are not
			// restoring the endpoint from a restart.
			identityLabels := labels.Labels{
				labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
			}
			regenTriggered := e.UpdateLabels(ctx, labels.LabelSourceAny, identityLabels, nil, true)
			if blocking {
				return regenTriggered, err
			}
		}
		return false, err
	}

	// Merge the labels retrieved from the 'resolveMetadata' into the base
	// labels.
	controllerBaseLabels.MergeLabels(k8sMetadata.IdentityLabels)

	e.SetPod(pod)
	e.SetK8sMetadata(k8sMetadata.ContainerPorts)
	e.UpdateNoTrackRules(func() string {
		value, _ := annotation.Get(pod, annotation.NoTrack, annotation.NoTrackAlias)
		return value
	}())
	e.UpdateBandwidthPolicy(
		pod.Annotations[bandwidth.EgressBandwidth],
		pod.Annotations[bandwidth.IngressBandwidth],
		pod.Annotations[bandwidth.Priority],
	)

	// If 'baseLabels' are not set then 'controllerBaseLabels' only contains
	// labels from k8s. Thus, we should only replace the labels that have their
	// source as 'k8s' otherwise we will risk on replacing other labels that
	// were added from other sources.
	source := labels.LabelSourceK8s
	if len(baseLabels) != 0 {
		source = labels.LabelSourceAny
	}
	regenTriggered = e.UpdateLabels(ctx, source, controllerBaseLabels, k8sMetadata.InfoLabels, blocking)

	return regenTriggered, nil
}

// K8sMetadata is a collection of Kubernetes-related metadata that are fetched
// from Kubernetes.
type K8sMetadata struct {
	ContainerPorts []slim_corev1.ContainerPort
	IdentityLabels labels.Labels
	InfoLabels     labels.Labels
}

// MetadataResolverCB provides an implementation for resolving the endpoint
// metadata for an endpoint such as the associated labels and annotations.
type MetadataResolverCB func(ns, podName, uid string) (pod *slim_corev1.Pod, k8sMetadata *K8sMetadata, err error)

// RunMetadataResolver starts a controller associated with the received
// endpoint which will periodically attempt to resolve the metadata for the
// endpoint and update the endpoint with the related. It stops resolving after
// either the first successful metadata resolution or when the endpoint is
// removed.
//
// baseLabels contains the list of labels use as "base" for the endpoint.
// The labels retrieved from 'MetadataResolverCB' will be merged into the
// baseLabels and put into the endpoint.
// If this list is empty, the labels set on the endpoint will be
// replaced by the labels returned 'MetadataResolverCB' as long their source
// matches the source of the labels already present on the endpoint.
//
// restoredEndpoint should be set to 'true' if the endpoint is being restored.
// If this is set to false and the resolver is unable to retrieve the endpoint
// labels from k8s, the endpoint will be set with the 'init' identity.
//
// blocking - will block this function until the endpoint receives a new
// security identity, and it is regenerated. If 'false', this
// operation will be done in the background and 'regenTriggered'
// will always be 'false'.
//
// This assumes that after the initial successful resolution, other mechanisms
// will handle updates (such as pkg/k8s/watchers informers).
func (e *Endpoint) RunMetadataResolver(restoredEndpoint, blocking bool, baseLabels labels.Labels, resolveMetadata MetadataResolverCB) (regenTriggered bool) {
	var regenTriggeredCh chan bool
	callerBlocked := false
	if blocking {
		regenTriggeredCh = make(chan bool)
		callerBlocked = true
	}
	controllerName := resolveLabels + "-" + e.GetK8sNamespaceAndPodName()

	e.controllers.UpdateController(controllerName,
		controller.ControllerParams{
			// Do not run this controller again after returning.
			RunInterval: 0,
			Group:       resolveLabelsControllerGroup,
			DoFunc: func(ctx context.Context) error {
				regenTriggered, err := e.metadataResolver(ctx, restoredEndpoint, blocking, baseLabels, resolveMetadata)

				// Check if the caller is still blocked.
				// It might already have been unblocked in a previous run, where resolving metadata
				// resulted in a regeneration even though it returned an error.
				if callerBlocked {
					select {
					case <-e.aliveCtx.Done():
					case regenTriggeredCh <- regenTriggered:
						// First regeneration will close the channel and unblock the caller.
						// This might be the case even if resolving metadata resulted in an error.
						close(regenTriggeredCh)
						callerBlocked = false
					}
				}

				return err
			},
			Context: e.aliveCtx,
		},
	)

	// If the caller wants this function to be blocking while resolving
	// identities / regenerating then we will wait for the first result of
	// `e.metadataResolver` before returning.
	if blocking {
		select {
		case regenTriggered, ok := <-regenTriggeredCh:
			return regenTriggered && ok
		case <-e.aliveCtx.Done():
			return false
		}
	}
	return false
}

// RunRestoredMetadataResolver starts a controller associated with the received
// endpoint which will periodically attempt to resolve the metadata for the
// endpoint and update the endpoint with the related. It stops resolving after
// either the first successful metadata resolution or when the endpoint is
// removed.
//
// This assumes that after the initial successful resolution, other mechanisms
// will handle updates (such as pkg/k8s/watchers informers).
func (e *Endpoint) RunRestoredMetadataResolver(resolveMetadata MetadataResolverCB) {
	e.RunMetadataResolver(true, false, nil, resolveMetadata)
}

// ModifyIdentityLabels changes the custom and orchestration identity labels of an endpoint.
// Labels can be added or deleted. If a label change is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(source string, addLabels, delLabels labels.Labels, updateJitter time.Duration) error {
	if err := e.lockAlive(); err != nil {
		return err
	}

	changed, err := e.labels.ModifyIdentityLabels(addLabels, delLabels)
	if err != nil {
		e.unlock()
		return err
	}

	// If the client made a request to modify labels, even if there was
	// no new labels added or deleted then we can safely remove the init
	// label. This is a workaround to allow the cilium-docker plugin
	// to remove endpoints in 'init' state if the containers were not
	// started with any label.
	if len(addLabels) == 0 && len(delLabels) == 0 && e.IsInit() {
		idLabls := e.labels.IdentityLabels()
		delete(idLabls, labels.IDNameInit)
		e.replaceIdentityLabels(source, idLabls)
		changed = true
	}
	if changed {
		// Mark with StateWaitingForIdentity, it will be set to
		// StateWaitingToRegenerate after the identity resolution has been
		// completed
		e.setState(StateWaitingForIdentity, "Triggering identity resolution due to updated identity labels")

		e.identityRevision++
	}
	e.unlock()

	if changed {
		e.runIdentityResolver(context.Background(), false, updateJitter)
	}
	return nil
}

// IsInit returns true if the endpoint still hasn't received identity labels,
// i.e. has the special identity with label reserved:init.
func (e *Endpoint) IsInit() bool {
	init, found := e.labels.GetIdentityLabel(labels.IDNameInit)
	return found && init.Source == labels.LabelSourceReserved
}

// InitWithIngressLabels initializes the endpoint with reserved:ingress.
// It should only be used for the ingress endpoint.
func (e *Endpoint) InitWithIngressLabels(ctx context.Context, launchTime time.Duration) {
	if !e.isIngress {
		return
	}

	epLabels := labels.Labels{}
	epLabels.MergeLabels(labels.LabelIngress)

	// Give the endpoint a security identity
	newCtx, cancel := context.WithTimeout(ctx, launchTime)
	defer cancel()
	e.UpdateLabels(newCtx, labels.LabelSourceAny, epLabels, epLabels, true)
	if errors.Is(newCtx.Err(), context.DeadlineExceeded) {
		e.getLogger().Warn("Timed out while updating security identify for host endpoint", logfields.Error, newCtx.Err())
	}
}

// InitWithNodeLabels initializes the endpoint with the known node labels as
// well as reserved:host. It should only be used for the host endpoint.
func (e *Endpoint) InitWithNodeLabels(ctx context.Context, nodeLabels map[string]string, launchTime time.Duration) {
	if !e.IsHost() {
		return
	}

	epLabels := labels.Labels{}
	epLabels.MergeLabels(labels.LabelHost)

	// Initialize with known node labels.
	newLabels := labels.Map2Labels(nodeLabels, labels.LabelSourceK8s)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	epLabels.MergeLabels(newIdtyLabels)

	// Give the endpoint a security identity
	newCtx, cancel := context.WithTimeout(ctx, launchTime)
	defer cancel()
	e.UpdateLabels(newCtx, labels.LabelSourceAny, epLabels, epLabels, true)
	if errors.Is(newCtx.Err(), context.DeadlineExceeded) {
		e.getLogger().Warn("Timed out while updating security identify for host endpoint", logfields.Error, newCtx.Err())
	}
}

// UpdateLabels is called to update the labels of an endpoint for the given
// 'sourceFilter', if 'source' is 'LabelSourceAny' then all labels are replaced.
// Calls to this function do not necessarily mean that the labels actually
// changed. The container runtime layer will periodically synchronize labels.
//
// The specified 'sourceFilter' will only remove the labels with that same
// source.
// For example:
// If the endpoint contains `k8s:foo=bar` and
// if 'sourceFilter' is 'cni' with labels `cni:bar=bar`, the result is:
//
//	`k8s:foo=bar` + `cni:bar=bar` - The "foo=bar" label is kept.
//
// if 'sourceFilter' is 'any' with labels `cni:bar=bar`, the result is:
//
//	`cni:bar=bar` - The "foo=bar" gets removed.
//
// If a net label changed was performed, the endpoint will receive a new
// security identity and will be regenerated. Both of these operations will
// run first synchronously if 'blocking' is true, and then in the background.
//
// Returns 'true' if endpoint regeneration was triggered.
func (e *Endpoint) UpdateLabels(ctx context.Context, sourceFilter string, identityLabels, infoLabels labels.Labels, blocking bool) (regenTriggered bool) {
	e.getLogger().Debug(
		"Refreshing labels of endpoint",
		logfields.SourceFilter, sourceFilter,
		logfields.IdentityLabels, identityLabels,
		logfields.InfoLabels, infoLabels,
	)

	if err := e.lockAlive(); err != nil {
		e.logDisconnectedMutexAction(err, "when trying to refresh endpoint labels")
		return false
	}

	e.replaceInformationLabels(sourceFilter, infoLabels)
	// replace identity labels and update the identity if labels have changed
	rev := e.replaceIdentityLabels(sourceFilter, identityLabels)

	// If the endpoint is in an 'init' state we need to remove this label
	// regardless of the "sourceFilter". Otherwise, we face risk of leaving the
	// endpoint with the reserved:init state forever.
	// We will perform the replacement only if:
	// - there are new identity labels being added;
	// - the sourceFilter is not any; If it is "any" then it was already
	//   replaced by the previous replaceIdentityLabels call.
	// - the new identity labels don't contain the reserved:init label
	// - the endpoint is in this init state.
	if len(identityLabels) != 0 &&
		sourceFilter != labels.LabelSourceAny &&
		!identityLabels.HasInitLabel() &&
		e.IsInit() {

		idLabls := e.labels.IdentityLabels()
		delete(idLabls, labels.IDNameInit)
		rev = e.replaceIdentityLabels(labels.LabelSourceAny, idLabls)
	}

	e.unlock()
	if rev != 0 {
		return e.runIdentityResolver(ctx, blocking, 0)
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

	ciliumIdentityMaxJitter := option.Config.CiliumIdentityMaxJitter
	err := e.ModifyIdentityLabels(source, newIdtyLabels, oldIdtyLabels, ciliumIdentityMaxJitter)
	if err != nil {
		e.getLogger().Debug(
			"Error while updating endpoint with new labels",
			logfields.Error, err,
		)
		return err
	}

	e.getLogger().Debug(
		"Updated endpoint with new labels",
		logfields.Labels, newIdtyLabels,
	)
	return nil
}

func (e *Endpoint) identityResolutionIsObsolete(myChangeRev int) bool {
	// Check if the endpoint has since received a new identity revision, if
	// so, abort as a new resolution routine will have been started.
	return myChangeRev != e.identityRevision
}

// runIdentityResolver resolves the numeric identity for the set of labels that
// are currently configured on the endpoint.
//
// Must be called with e.mutex NOT held.
func (e *Endpoint) runIdentityResolver(ctx context.Context, blocking bool, updateJitter time.Duration) (regenTriggered bool) {
	err := e.rlockAlive()
	if err != nil {
		// If a labels update and an endpoint delete API request arrive
		// in quick succession, this could occur; in that case, there's
		// no point updating the controller.
		e.getLogger().Info(
			"Cannot run labels resolver",
			logfields.Error, err,
		)
		return false
	}
	newLabels := e.labels.IdentityLabels()
	e.runlock()
	scopedLog := e.getLogger().With(logfields.IdentityLabels, newLabels)

	// If we are certain we can resolve the identity without accessing the KV
	// store, do it first synchronously right now. This can reduce the number
	// of regenerations for the endpoint during its initialization.
	regenTriggered = false
	if blocking || identity.IdentityAllocationIsLocal(newLabels) {
		scopedLog.Info("Resolving identity labels (blocking)")
		regenTriggered, err = e.identityLabelsChanged(ctx)
		if err != nil {
			if errors.Is(err, ErrNotAlive) {
				scopedLog.Debug("not changing endpoint identity because endpoint is in process of being removed")
				return false
			}
			scopedLog.Warn("Error changing endpoint identity", logfields.Error, err)
		}
	} else {
		scopedLog.Info("Resolving identity labels (non-blocking)")
	}

	ctrlName := resolveIdentity + "-" + strconv.FormatUint(uint64(e.ID), 10)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			Group: resolveIdentityControllerGroup,
			DoFunc: func(ctx context.Context) error {
				_, err := e.identityLabelsChanged(ctx)
				if errors.Is(err, ErrNotAlive) {
					e.getLogger().Debug("not changing endpoint identity because endpoint is in process of being removed")
					return controller.NewExitReason("Endpoint disappeared")
				}
				return err
			},
			RunInterval: 5 * time.Minute,
			Context:     e.aliveCtx,
			Jitter:      updateJitter,
		},
	)

	return regenTriggered
}

func (e *Endpoint) identityLabelsChanged(ctx context.Context) (regenTriggered bool, err error) {
	// e.setState() called below, can't take a read lock.
	if err := e.lockAlive(); err != nil {
		return false, err
	}
	newLabels := e.labels.IdentityLabels()
	myChangeRev := e.identityRevision
	scopedLog := e.getLogger().With(
		logfields.IdentityLabels, newLabels,
	)

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.unlock()
		scopedLog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return false, nil
	}

	if e.SecurityIdentity != nil && e.SecurityIdentity.Labels.Equals(newLabels) {
		// Sets endpoint state to ready if was waiting for identity
		if e.getState() == StateWaitingForIdentity {
			e.setState(StateReady, "Set identity for this endpoint")
		}
		e.unlock()
		scopedLog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return false, nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.unlock()
	scopedLog.Debug("Resolving identity for labels")

	// Typically, SelectorCache notification happens from the identityWatcher,
	// requiring a round-trip to the kvstore to start updating policies for
	// other endpoints on the node.
	//
	// To get a jump start on plumbing the handling of the identity for
	// this endpoint, trigger the early notification via this call. If the
	// identity is new, then this will start updating the policy for other
	// co-located endpoints without having to wait for that RTT.
	//
	// This must happen before triggering regeration, as this ID must be
	// plumbed in to the SelectorCache in order for policy to correctly apply
	// to this endpoint. Fortunately AllocateIdentity() will synchronously
	// update the SelectorCache, so there are no problems here.
	notifySelectorCache := true
	allocatedIdentity, _, err := e.allocator.AllocateIdentity(ctx, newLabels, notifySelectorCache, identity.InvalidIdentity)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %w", err)
		e.LogStatus(Other, Warning, err.Error()+" (will retry)")
		return false, err
	}

	// When releasing identities after allocation due to either failure of
	// allocation or due a no longer used identity we want to operation to
	// continue even if the parent has given up. The Release operation
	// has an internal timeout based on the configuration to avoid blocking
	// forever in case of connectivity problems.
	releaseNewlyAllocatedIdentity := func() {
		_, err := e.allocator.Release(context.Background(), allocatedIdentity, false)
		if err != nil {
			// non fatal error as keys will expire after lease expires but log it
			scopedLog.Warn(
				"Unable to release newly allocated identity again",
				logfields.Error, err,
				logfields.IdentityNew, allocatedIdentity.ID,
			)
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

			scopedLog.Debug("Applying grace period before regeneration due to identity change")
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

	scopedLog.Debug(
		"Assigned new identity to endpoint",
		logfields.IdentityNew, allocatedIdentity.StringID(),
	)

	e.SetIdentity(allocatedIdentity, false)

	if oldIdentity != nil {
		_, err := e.allocator.Release(context.Background(), oldIdentity, false)
		if err != nil {
			scopedLog.Warn(
				"Unable to release old endpoint identity",
				logfields.Error, err,
				logfields.IdentityOld, oldIdentity.ID,
			)
		}
	}

	readyToRegenerate := false
	regenMetadata := &regeneration.ExternalRegenerationMetadata{
		Reason:            "updated security labels",
		RegenerationLevel: regeneration.RegenerateWithDatapath,
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
	// Wait for any in-progress regenerations to finish.
	e.buildMutex.Lock()
	defer e.buildMutex.Unlock()

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
	e.UpdateLogger(map[string]any{
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
//   - the endpoint is disconnected state
//   - the endpoint's policy revision reaches the wanted revision
//
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

func (e *Endpoint) syncEndpointHeaderFile(reasons []string) {
	e.buildMutex.Lock()
	defer e.buildMutex.Unlock()

	startTime := time.Now()
	// The following GetDNSRules call will acquire a read-lock on the IPCache.
	// Because IPCache itself will potentially acquire endpoint locks in its
	// critical section, we must _not_ hold endpoint.mutex while calling
	// GetDNSRules, to avoid a deadlock between IPCache and the endpoint. It is
	// okay to hold endpoint.buildMutex, however.
	rules := e.dnsRulesAPI.GetDNSRules(e.ID)

	if err := e.lockAlive(); err != nil {
		// endpoint was removed in the meanwhile, return
		return
	}
	defer e.unlock()

	// Update DNSRules if any. This is needed because DNSRules also encode allowed destination IPs
	// and those can change anytime we have identity updates in the cluster.
	e.setDNSRulesLocked(rules)

	if err := e.writeHeaderfile(e.StateDirectoryPath()); err != nil {
		e.getLogger().Warn(
			"Could not sync header file",
			logfields.Error, err,
			logfields.Reason, reasons,
		)
	} else {
		e.getLogger().Debug("Endpoint header and config file sync completed",
			logfields.Reason, reasons,
			logfields.Duration, time.Since(startTime))
	}
}

// SyncEndpointHeaderFile triggers the header file sync to the ep_config.h
// file. This includes updating the current DNS History information.
func (e *Endpoint) SyncEndpointHeaderFile() {
	if trigger := e.dnsHistoryTrigger.Load(); trigger != nil {
		trigger.TriggerWithReason("SyncEndpointDNSState")
	}
}

// Delete cleans up all resources associated with this endpoint, including the
// following:
// * all goroutines managed by this Endpoint (EventQueue, Controllers)
// * removal from the endpointmanager, resulting in new events not taking effect
// on this endpoint
// * cleanup of datapath state (BPF maps, proxy configuration, directories)
// * releasing of the reference to its allocated security identity
func (e *Endpoint) Delete(conf DeleteConfig) []error {
	errs := []error{}

	e.Stop()

	// Wait for any pending endpoint regenerate() calls to finish. The
	// latter bails out after taking the lock when it detects that the
	// endpoint state is disconnecting.
	e.buildMutex.Lock()
	defer e.buildMutex.Unlock()

	// Lock out any other writers to the endpoint.  In case multiple delete
	// requests have been enqueued, have all of them except the first
	// return here. Ignore the request if the endpoint is already
	// disconnected.
	if err := e.lockAlive(); err != nil {
		return []error{}
	}
	e.setState(StateDisconnecting, "Deleting endpoint")

	if option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure || option.Config.IPAM == ipamOption.IPAMAlibabaCloud ||
		(option.Config.IPAM == ipamOption.IPAMDelegatedPlugin && option.Config.InstallUplinkRoutesForDelegatedIPAM) {
		e.getLogger().Debug(
			"Deleting endpoint routing rules",
		)

		// This is a best-effort attempt to cleanup. We expect there to be one
		// ingress rule and multiple egress rules. If we find more rules than
		// expected, we delete all rules referring to a per-ENI routing table ID.
		if e.IPv4.IsValid() {
			if err := linuxrouting.Delete(e.getLogger(), e.IPv4, option.Config.EgressMultiHomeIPRuleCompat); err != nil {
				errs = append(errs, fmt.Errorf("unable to delete endpoint routing rules: %w", err))
			}
		}

		if e.IPv6.IsValid() {
			if err := linuxrouting.Delete(e.getLogger(), e.IPv6, option.Config.EgressMultiHomeIPRuleCompat); err != nil {
				errs = append(errs, fmt.Errorf("unable to delete endpoint routing rules: %w", err))
			}
		}
	}

	if e.noTrackPort > 0 {
		e.getLogger().Debug(
			"Deleting endpoint NOTRACK rules",
		)

		if e.IPv4.IsValid() {
			e.ipTablesManager.RemoveNoTrackRules(e.IPv4, e.noTrackPort)
		}
		if e.IPv6.IsValid() {
			e.ipTablesManager.RemoveNoTrackRules(e.IPv6, e.noTrackPort)
		}
	}

	// If dry mode is enabled, no changes to system state are made.
	if !e.isProperty(PropertyFakeEndpoint) {
		// Set the Endpoint's interface down to prevent it from passing any traffic
		// after its tc filters are removed.
		if err := e.setDown(); err != nil {
			errs = append(errs, err)
		}

		// Detach the endpoint program from any tc(x) hooks.
		e.orchestrator.Unload(e.createEpInfoCache(""))

		// Delete the endpoint's entries from the global cilium_(egress)call_policy
		// maps and remove per-endpoint cilium_calls_ and cilium_policy_v2_ map pins.
		if err := e.deleteMaps(); err != nil {
			errs = append(errs, err...)
		}
	}

	errs = append(errs, e.leaveLocked(conf)...)
	e.unlock()

	return errs
}

// setDown sets the Endpoint's underlying interface down. If the interface
// cannot be retrieved, returns nil.
func (e *Endpoint) setDown() error {
	link, err := safenetlink.LinkByName(e.HostInterface())
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		// No interface, nothing to do.
		return nil
	}
	if err != nil {
		return fmt.Errorf("setting interface %s down: %w", e.HostInterface(), err)
	}

	return netlink.LinkSetDown(link)
}

// WaitForFirstRegeneration waits for the endpoint to complete its first full regeneration.
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
			e.runlock()
		}

		if ctx.Err() != nil {
			return fmt.Errorf("timeout while waiting for initial endpoint generation to complete: %w", ctx.Err())
		}
	}
}

// SetDefaultConfiguration sets the default configuration options for its
// boolean configuration options and for policy enforcement based off of the
// global policy enforcement configuration options. If the configuration option to
// keep endpoint configuration during endpoint restore is enabled, this is a
// no-op.
func (e *Endpoint) SetDefaultConfiguration() {
	e.unconditionalLock()
	defer e.unlock()

	if option.Config.KeepConfig {
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

// GetPropertyValue returns the metadata value for this key.
func (e *Endpoint) GetPropertyValue(key string) any {
	e.mutex.RWMutex.RLock()
	defer e.mutex.RWMutex.RUnlock()
	return e.properties[key]
}

// SetPropertyValue sets the metadata value for this key.
func (e *Endpoint) SetPropertyValue(key string, value any) any {
	e.mutex.RWMutex.Lock()
	defer e.mutex.RWMutex.Unlock()
	old := e.properties[key]
	e.properties[key] = value
	return old
}

// IsProperty checks if the value of the properties map is set, it's a boolean
// and its value is 'true'.
func (e *Endpoint) IsProperty(propertyKey string) bool {
	e.mutex.RWMutex.RLock()
	defer e.mutex.RWMutex.RUnlock()
	return e.isProperty(propertyKey)
}

// isProperty checks if the value of the properties map is set, it's a boolean
// and its value is 'true'.
func (e *Endpoint) isProperty(propertyKey string) bool {
	if v, ok := e.properties[propertyKey]; ok {
		isSet, ok := v.(bool)
		return ok && isSet
	}
	return false
}

func (e *Endpoint) GetContainerNetnsPath() string {
	return e.containerNetnsPath
}
