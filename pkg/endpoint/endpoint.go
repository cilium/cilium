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
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/model"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	bpfconfig "github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/notifications"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/distillery"
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

	// HealthCEPPrefix is the prefix used to name the cilium health endpoints' CEP
	HealthCEPPrefix = "cilium-health-"
)

// compile time interface check
var _ notifications.RegenNotificationInfo = &Endpoint{}

// Endpoint represents a container or similar which can be individually
// addresses on L3 with its own IP addresses. This structured is managed by the
// endpoint manager in pkg/endpointmanager.
//
//
// WARNING - STABLE API
// This structure is written as JSON to StateDir/{ID}/lxc_config.h to allow to
// restore endpoints when the agent is being restarted. The restore operation
// will read the file and re-create all endpoints with all fields which are not
// marked as private to JSON marshal. Do NOT modify this structure in ways which
// is not JSON forward compatible.
//
type Endpoint struct {
	// ID of the endpoint, unique in the scope of the node
	ID uint16

	// mutex protects write operations to this endpoint structure except
	// for the logger field which has its own mutex
	mutex lock.RWMutex

	// ContainerName is the name given to the endpoint by the container runtime
	ContainerName string

	// ContainerID is the container ID that docker has assigned to the endpoint
	// Note: The JSON tag was kept for backward compatibility.
	ContainerID string `json:"dockerID,omitempty"`

	// DockerNetworkID is the network ID of the libnetwork network if the
	// endpoint is a docker managed container which uses libnetwork
	DockerNetworkID string

	// DockerEndpointID is the Docker network endpoint ID if managed by
	// libnetwork
	DockerEndpointID string

	// Corresponding BPF map identifier for tail call map of ipvlan datapath
	DatapathMapID int

	// isDatapathMapPinned denotes whether the datapath map has been pinned.
	isDatapathMapPinned bool

	// IfName is the name of the host facing interface (veth pair) which
	// connects into the endpoint
	IfName string

	// IfIndex is the interface index of the host face interface (veth pair)
	IfIndex int

	// OpLabels is the endpoint's label configuration
	//
	// FIXME: Rename this field to Labels
	OpLabels pkgLabels.OpLabels

	// identityRevision is incremented each time the identity label
	// information of the endpoint has changed
	identityRevision int

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

	// SecurityIdentity is the security identity of this endpoint. This is computed from
	// the endpoint's labels.
	SecurityIdentity *identityPkg.Identity `json:"SecLabel"`

	// hasSidecarProxy indicates whether the endpoint has been injected by
	// Istio with a Cilium-compatible sidecar proxy. If true, the sidecar proxy
	// will be used to apply L7 policy rules. Otherwise, Cilium's node-wide
	// proxy will be used.
	// TODO: Currently this applies only to HTTP L7 rules. Kafka L7 rules are still enforced by Cilium's node-wide Kafka proxy.
	hasSidecarProxy bool

	// prevIdentityCacheRevision is the revision of the identity cache used in the
	// previous policy computation
	prevIdentityCacheRevision uint64

	// PolicyMap is the policy related state of the datapath including
	// reference to all policy related BPF
	PolicyMap *policymap.PolicyMap `json:"-"`

	// Options determine the datapath configuration of the endpoint.
	Options *option.IntOptions

	// Status are the last n state transitions this endpoint went through
	Status *EndpointStatus

	// DNSHistory is the collection of still-valid DNS responses intercepted for
	// this endpoint.
	DNSHistory *fqdn.DNSCache

	// dnsHistoryTrigger is the trigger to write down the lxc_config.h to make
	// sure that restores when DNS policy is in there are correct
	dnsHistoryTrigger *trigger.Trigger

	// state is the state the endpoint is in. See SetStateLocked()
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

	// proxyStatistics contains statistics of proxy redirects.
	// They keys in this map are the ProxyStatistics with their
	// AllocatedProxyPort and Statistics fields set to 0 and nil.
	// You must hold Endpoint.proxyStatisticsMutex to read or write it.
	proxyStatistics map[models.ProxyStatistics]*models.ProxyStatistics

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
	BuildMutex lock.Mutex `json:"-"`

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

	// BPFConfigMap provides access to the endpoint's BPF configuration.
	bpfConfigMap *bpfconfig.EndpointConfigMap

	// desiredBPFConfig is the BPF Configuration computed from the endpoint.
	desiredBPFConfig *bpfconfig.EndpointConfig

	// realizedBPFConfig is the config currently active in the BPF datapath.
	realizedBPFConfig *bpfconfig.EndpointConfig

	// ctCleaned indicates whether the conntrack table has already been
	// cleaned when this endpoint was first created
	ctCleaned bool

	hasBPFProgram chan struct{}

	// selectorPolicy represents a reference to the shared SelectorPolicy
	// for all endpoints that have the same Identity.
	selectorPolicy distillery.SelectorPolicy

	desiredPolicy *policy.EndpointPolicy

	realizedPolicy *policy.EndpointPolicy

	EventQueue *eventqueue.EventQueue `json:"-"`

	///////////////////////
	// DEPRECATED FIELDS //
	///////////////////////

	// DeprecatedOpts represents the mutable options for the endpoint, in
	// the format understood by Cilium 1.1 or earlier.
	//
	// Deprecated: Use Options instead.
	DeprecatedOpts deprecatedOptions `json:"Opts"`
}

// UpdateController updates the controller with the specified name with the
// provided list of parameters in endpoint's list of controllers.
func (e *Endpoint) UpdateController(name string, params controller.ControllerParams) *controller.Controller {
	return e.controllers.UpdateController(name, params)
}

// CloseBPFProgramChannel closes the channel that signals whether the endpoint
// has had its BPF program compiled. If the channel is already closed, this is
// a no-op.
func (e *Endpoint) CloseBPFProgramChannel() {
	select {
	case <-e.hasBPFProgram:
	default:
		close(e.hasBPFProgram)
	}
}

// HasBPFProgram returns whether a BPF program has been generated for this
// endpoint.
func (e *Endpoint) HasBPFProgram() bool {
	select {
	case <-e.hasBPFProgram:
		return true
	default:
		return false
	}
}

// HasIpvlanDataPath returns whether the daemon is running in ipvlan mode.
func (e *Endpoint) HasIpvlanDataPath() bool {
	if e.DatapathMapID > 0 {
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

// SetDesiredIngressPolicyEnabled sets Endpoint's ingress policy enforcement
// configuration to the specified value. The endpoint's mutex must not be held.
func (e *Endpoint) SetDesiredIngressPolicyEnabled(ingress bool) {
	e.UnconditionalLock()
	e.desiredPolicy.IngressPolicyEnabled = ingress
	e.Unlock()

}

// SetDesiredEgressPolicyEnabled sets Endpoint's egress policy enforcement
// configuration to the specified value. The endpoint's mutex must not be held.
func (e *Endpoint) SetDesiredEgressPolicyEnabled(egress bool) {
	e.UnconditionalLock()
	e.desiredPolicy.EgressPolicyEnabled = egress
	e.Unlock()
}

// SetDesiredIngressPolicyEnabledLocked sets Endpoint's ingress policy enforcement
// configuration to the specified value. The endpoint's mutex must be held.
func (e *Endpoint) SetDesiredIngressPolicyEnabledLocked(ingress bool) {
	e.desiredPolicy.IngressPolicyEnabled = ingress
}

// SetDesiredEgressPolicyEnabledLocked sets Endpoint's egress policy enforcement
// configuration to the specified value. The endpoint's mutex must be held.
func (e *Endpoint) SetDesiredEgressPolicyEnabledLocked(egress bool) {
	e.desiredPolicy.EgressPolicyEnabled = egress
}

// WaitForProxyCompletions blocks until all proxy changes have been completed.
// Called with BuildMutex held.
func (e *Endpoint) WaitForProxyCompletions(proxyWaitGroup *completion.WaitGroup) error {
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
func NewEndpointWithState(ID uint16, state string) *Endpoint {
	ep := &Endpoint{
		ID:             ID,
		OpLabels:       pkgLabels.NewOpLabels(),
		Status:         NewEndpointStatus(),
		DNSHistory:     fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		state:          state,
		hasBPFProgram:  make(chan struct{}, 0),
		controllers:    controller.NewManager(),
		EventQueue:     eventqueue.NewEventQueueBuffered(fmt.Sprintf("endpoint-%d", ID), option.Config.EndpointQueueSize),
		desiredPolicy:  policy.NewEndpointPolicy(),
		realizedPolicy: policy.NewEndpointPolicy(),
	}
	ep.SetDefaultOpts(option.Config.Opts)
	ep.UpdateLogger(nil)

	ep.EventQueue.Run()

	return ep
}

// NewEndpointFromChangeModel creates a new endpoint from a request
func NewEndpointFromChangeModel(base *models.EndpointChangeRequest) (*Endpoint, error) {
	if base == nil {
		return nil, nil
	}

	ep := &Endpoint{
		ID:               uint16(base.ID),
		ContainerName:    base.ContainerName,
		ContainerID:      base.ContainerID,
		DockerNetworkID:  base.DockerNetworkID,
		DockerEndpointID: base.DockerEndpointID,
		IfName:           base.InterfaceName,
		K8sPodName:       base.K8sPodName,
		K8sNamespace:     base.K8sNamespace,
		DatapathMapID:    int(base.DatapathMapID),
		IfIndex:          int(base.InterfaceIndex),
		OpLabels:         pkgLabels.NewOpLabels(),
		DNSHistory:       fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
		state:            "",
		Status:           NewEndpointStatus(),
		hasBPFProgram:    make(chan struct{}, 0),
		desiredPolicy:    policy.NewEndpointPolicy(),
		realizedPolicy:   policy.NewEndpointPolicy(),
		controllers:      controller.NewManager(),
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

	ep.SetDefaultOpts(option.Config.Opts)

	ep.UpdateLogger(nil)
	ep.SetStateLocked(string(base.State), "Endpoint creation")

	return ep, nil
}

// GetModelRLocked returns the API model of endpoint e.
// e.mutex must be RLocked.
func (e *Endpoint) GetModelRLocked() *models.Endpoint {
	if e == nil {
		return nil
	}

	currentState := models.EndpointState(e.state)
	if currentState == models.EndpointStateReady && e.Status.CurrentStatus() != OK {
		currentState = models.EndpointStateNotReady
	}

	// This returns the most recent log entry for this endpoint. It is backwards
	// compatible with the json from before we added `cilium endpoint log` but it
	// only returns 1 entry.
	statusLog := e.Status.GetModel()
	if len(statusLog) > 0 {
		statusLog = statusLog[:1]
	}

	lblMdl := model.NewModel(&e.OpLabels)

	// Sort these slices since they come out in random orders. This allows
	// reflect.DeepEqual to succeed.
	sort.StringSlice(lblMdl.Realized.User).Sort()
	sort.StringSlice(lblMdl.Disabled).Sort()
	sort.StringSlice(lblMdl.SecurityRelevant).Sort()
	sort.StringSlice(lblMdl.Derived).Sort()

	controllerMdl := e.controllers.GetStatusModel()
	sort.Slice(controllerMdl, func(i, j int) bool { return controllerMdl[i].Name < controllerMdl[j].Name })

	spec := &models.EndpointConfigurationSpec{
		LabelConfiguration: lblMdl.Realized,
	}

	if e.Options != nil {
		spec.Options = *e.Options.GetMutableModel()
	}

	mdl := &models.Endpoint{
		ID:   int64(e.ID),
		Spec: spec,
		Status: &models.EndpointStatus{
			// FIXME GH-3280 When we begin implementing revision numbers this will
			// diverge from models.Endpoint.Spec to reflect the in-datapath config
			Realized: spec,
			Identity: e.SecurityIdentity.GetModel(),
			Labels:   lblMdl,
			Networking: &models.EndpointNetworking{
				Addressing: []*models.AddressPair{{
					IPV4: e.IPv4.String(),
					IPV6: e.IPv6.String(),
				}},
				InterfaceIndex: int64(e.IfIndex),
				InterfaceName:  e.IfName,
				Mac:            e.LXCMAC.String(),
				HostMac:        e.NodeMAC.String(),
			},
			ExternalIdentifiers: &models.EndpointIdentifiers{
				ContainerID:      e.ContainerID,
				ContainerName:    e.ContainerName,
				DockerEndpointID: e.DockerEndpointID,
				DockerNetworkID:  e.DockerNetworkID,
				PodName:          e.GetK8sNamespaceAndPodNameLocked(),
			},
			// FIXME GH-3280 When we begin returning endpoint revisions this should
			// change to return the configured and in-datapath policies.
			Policy:      e.GetPolicyModel(),
			Log:         statusLog,
			Controllers: controllerMdl,
			State:       currentState, // TODO: Validate
			Health:      e.getHealthModel(),
		},
	}

	return mdl
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
	// NOTE: Using rlock on mutex directly because getHealthModel handles removed endpoint properly
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.getHealthModel()
}

// GetModel returns the API model of endpoint e.
func (e *Endpoint) GetModel() *models.Endpoint {
	if e == nil {
		return nil
	}
	// NOTE: Using rlock on mutex directly because GetModelRLocked handles removed endpoint properly
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	return e.GetModelRLocked()
}

// GetPolicyModel returns the endpoint's policy as an API model.
//
// Must be called with e.Mutex locked.
func (e *Endpoint) GetPolicyModel() *models.EndpointPolicyStatus {
	if e == nil {
		return nil
	}

	if e.SecurityIdentity == nil {
		return nil
	}

	realizedIngressIdentities := make([]int64, 0)
	realizedEgressIdentities := make([]int64, 0)

	for policyMapKey := range e.realizedPolicy.PolicyMapState {
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		switch trafficdirection.TrafficDirection(policyMapKey.TrafficDirection) {
		case trafficdirection.Ingress:
			realizedIngressIdentities = append(realizedIngressIdentities, int64(policyMapKey.Identity))
		case trafficdirection.Egress:
			realizedEgressIdentities = append(realizedEgressIdentities, int64(policyMapKey.Identity))
		default:
			log.WithField(logfields.TrafficDirection, trafficdirection.TrafficDirection(policyMapKey.TrafficDirection)).Error("Unexpected traffic direction present in realized PolicyMap state for endpoint")
		}
	}

	desiredIngressIdentities := make([]int64, 0)
	desiredEgressIdentities := make([]int64, 0)

	for policyMapKey := range e.desiredPolicy.PolicyMapState {
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the Key no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		switch trafficdirection.TrafficDirection(policyMapKey.TrafficDirection) {
		case trafficdirection.Ingress:
			desiredIngressIdentities = append(desiredIngressIdentities, int64(policyMapKey.Identity))
		case trafficdirection.Egress:
			desiredEgressIdentities = append(desiredEgressIdentities, int64(policyMapKey.Identity))
		default:
			log.WithField(logfields.TrafficDirection, trafficdirection.TrafficDirection(policyMapKey.TrafficDirection)).Error("Unexpected traffic direction present in desired PolicyMap state for endpoint")
		}
	}

	policyEnabled := e.policyStatus()

	e.proxyStatisticsMutex.RLock()
	proxyStats := make([]*models.ProxyStatistics, 0, len(e.proxyStatistics))
	for _, stats := range e.proxyStatistics {
		proxyStats = append(proxyStats, stats.DeepCopy())
	}
	e.proxyStatisticsMutex.RUnlock()
	sortProxyStats(proxyStats)

	var (
		realizedCIDRPolicy *policy.CIDRPolicy
		realizedL4Policy   *policy.L4Policy
	)
	if e.realizedPolicy != nil {
		realizedL4Policy = e.realizedPolicy.L4Policy
		realizedCIDRPolicy = e.realizedPolicy.CIDRPolicy
	}

	mdl := &models.EndpointPolicy{
		ID: int64(e.SecurityIdentity.ID),
		// This field should be removed.
		Build:                    int64(e.policyRevision),
		PolicyRevision:           int64(e.policyRevision),
		AllowedIngressIdentities: realizedIngressIdentities,
		AllowedEgressIdentities:  realizedEgressIdentities,
		CidrPolicy:               realizedCIDRPolicy.GetModel(),
		L4:                       realizedL4Policy.GetModel(),
		PolicyEnabled:            policyEnabled,
	}

	var (
		desiredCIDRPolicy *policy.CIDRPolicy
		desiredL4Policy   *policy.L4Policy
	)
	if e.desiredPolicy != nil {
		desiredL4Policy = e.desiredPolicy.L4Policy
		desiredCIDRPolicy = e.desiredPolicy.CIDRPolicy
	} else {
		desiredL4Policy = &policy.L4Policy{}
		desiredCIDRPolicy = &policy.CIDRPolicy{}
	}

	desiredMdl := &models.EndpointPolicy{
		ID: int64(e.SecurityIdentity.ID),
		// This field should be removed.
		Build:                    int64(e.nextPolicyRevision),
		PolicyRevision:           int64(e.nextPolicyRevision),
		AllowedIngressIdentities: desiredIngressIdentities,
		AllowedEgressIdentities:  desiredEgressIdentities,
		CidrPolicy:               desiredCIDRPolicy.GetModel(),
		L4:                       desiredL4Policy.GetModel(),
		PolicyEnabled:            policyEnabled,
	}
	// FIXME GH-3280 Once we start returning revisions Realized should be the
	// policy implemented in the data path
	return &models.EndpointPolicyStatus{
		Spec:                desiredMdl,
		Realized:            mdl,
		ProxyPolicyRevision: int64(e.proxyPolicyRevision),
		ProxyStatistics:     proxyStats,
	}
}

// policyStatus returns the endpoint's policy status
//
// Must be called with e.Mutex locked.
func (e *Endpoint) policyStatus() models.EndpointPolicyEnabled {
	policyEnabled := models.EndpointPolicyEnabledNone
	switch {
	case e.realizedPolicy.IngressPolicyEnabled && e.realizedPolicy.EgressPolicyEnabled:
		policyEnabled = models.EndpointPolicyEnabledBoth
	case e.realizedPolicy.IngressPolicyEnabled:
		policyEnabled = models.EndpointPolicyEnabledIngress
	case e.realizedPolicy.EgressPolicyEnabled:
		policyEnabled = models.EndpointPolicyEnabledEgress
	}
	return policyEnabled
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
func (e *Endpoint) GetSecurityIdentity() *identityPkg.Identity {
	return e.SecurityIdentity
}

// GetID16 returns the endpoint's ID as a 16-bit unsigned integer.
func (e *Endpoint) GetID16() uint16 {
	return e.ID
}

// GetK8sPodLabels returns all labels that exist in the endpoint and were
// derived from k8s pod.
func (e *Endpoint) GetK8sPodLabels() pkgLabels.Labels {
	e.UnconditionalRLock()
	defer e.RUnlock()
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
	e.UnconditionalRLock()
	defer e.RUnlock()
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
	return e.NodeMAC
}

// SetNodeMACLocked updates the node MAC inside the endpoint.
func (e *Endpoint) SetNodeMACLocked(m mac.MAC) {
	e.NodeMAC = m
}

func (e *Endpoint) HasSidecarProxy() bool {
	return e.hasSidecarProxy
}

// ConntrackName returns the name suffix for the endpoint-specific bpf
// conntrack map, which is a 5-digit endpoint ID, or "global" when the
// global map should be used.
// Must be called with the endpoint locked.
func (e *Endpoint) ConntrackName() string {
	if e.ConntrackLocalLocked() {
		return fmt.Sprintf("%05d", int(e.ID))
	}
	return "global"
}

// StringID returns the endpoint's ID in a string.
func (e *Endpoint) StringID() string {
	return strconv.Itoa(int(e.ID))
}

func (e *Endpoint) GetIdentity() identityPkg.NumericIdentity {
	if e.SecurityIdentity != nil {
		return e.SecurityIdentity.ID
	}

	return identityPkg.InvalidIdentity
}

func (e *Endpoint) Allows(id identityPkg.NumericIdentity) bool {
	e.UnconditionalRLock()
	defer e.RUnlock()

	keyToLookup := policy.Key{
		Identity:         uint32(id),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}

	_, ok := e.desiredPolicy.PolicyMapState[keyToLookup]
	return ok
}

// String returns endpoint on a JSON format.
func (e *Endpoint) String() string {
	e.UnconditionalRLock()
	defer e.RUnlock()
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

// ForcePolicyCompute marks the endpoint for forced bpf regeneration.
func (e *Endpoint) ForcePolicyCompute() {
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
	e.UnconditionalRLock()
	defer e.RUnlock()

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

	transformEndpointForDowngrade(e)
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
	return json.Unmarshal(jsonBytes, ep)
}

// FilterEPDir returns a list of directories' names that possible belong to an endpoint.
func FilterEPDir(dirFiles []os.FileInfo) []string {
	eptsID := []string{}
	for _, file := range dirFiles {
		if file.IsDir() {
			_, err := strconv.ParseUint(file.Name(), 10, 16)
			if err == nil || strings.HasSuffix(file.Name(), "_next") || strings.HasSuffix(file.Name(), "_next_fail") {
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
	ep := Endpoint{
		OpLabels:   pkgLabels.NewOpLabels(),
		DNSHistory: fqdn.NewDNSCacheWithLimit(option.Config.ToFQDNsMinTTL, option.Config.ToFQDNsMaxIPsPerHost),
	}
	if err := parseBase64ToEndpoint(strEpSlice[1], &ep); err != nil {
		return nil, fmt.Errorf("failed to parse base64toendpoint: %s", err)
	}

	// Validate the options that were parsed
	ep.SetDefaultOpts(ep.Options)

	// Initialize fields to values which are non-nil that are not serialized.
	ep.hasBPFProgram = make(chan struct{}, 0)
	ep.desiredPolicy = policy.NewEndpointPolicy()
	ep.realizedPolicy = policy.NewEndpointPolicy()
	ep.controllers = controller.NewManager()

	// We need to check for nil in Status, CurrentStatuses and Log, since in
	// some use cases, status will be not nil and Cilium will eventually
	// error/panic if CurrentStatus or Log are not initialized correctly.
	// Reference issue GH-2477
	if ep.Status == nil || ep.Status.CurrentStatuses == nil || ep.Status.Log == nil {
		ep.Status = NewEndpointStatus()
	}

	if ep.SecurityIdentity == nil {
		ep.SetIdentity(identityPkg.LookupReservedIdentity(identityPkg.ReservedIdentityInit))
	} else {
		ep.SecurityIdentity.Sanitize()
	}
	ep.UpdateLogger(nil)

	ep.SetStateLocked(StateRestoring, "Endpoint restoring")

	return &ep, nil
}

func (e *Endpoint) LogStatus(typ StatusType, code StatusCode, msg string) {
	e.UnconditionalLock()
	defer e.Unlock()
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
	e.Status.indexMU.Lock()
	defer e.Status.indexMU.Unlock()
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
func (e *Endpoint) Update(owner Owner, cfg *models.EndpointConfigurationSpec) error {
	om, err := EndpointMutableOptionLibrary.ValidateConfigurationMap(cfg.Options)
	if err != nil {
		return UpdateValidationError{err.Error()}
	}

	if err := e.LockAlive(); err != nil {
		return err
	}

	e.getLogger().WithField("configuration-options", cfg).Debug("updating endpoint configuration options")

	// CurrentStatus will be not OK when we have an uncleared error in BPF,
	// policy or Other. We should keep trying to regenerate in the hopes of
	// suceeding.
	// Note: This "retry" behaviour is better suited to a controller, and can be
	// moved there once we have an endpoint regeneration controller.
	regenCtx := &ExternalRegenerationMetadata{
		Reason: "endpoint was updated via API",
	}

	// If configuration options are provided, we only regenerate if necessary.
	// Otherwise always regenerate.
	if cfg.Options == nil {
		regenCtx.RegenerationLevel = RegenerateWithDatapathRebuild
		regenCtx.Reason = "endpoint was manually regenerated via API"
	} else if e.updateAndOverrideEndpointOptions(om) || e.Status.CurrentStatus() != OK {
		regenCtx.RegenerationLevel = RegenerateWithDatapathRewrite
	}

	if regenCtx.RegenerationLevel > RegenerateWithoutDatapath {
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

		e.Unlock()
		for {
			select {
			case <-ticker.C:
				if err := e.LockAlive(); err != nil {
					return err
				}
				// Check endpoint state before attempting configuration update because
				// configuration updates can only be applied when the endpoint is in
				// specific states. See GH-3058.
				stateTransitionSucceeded := e.SetStateLocked(StateWaitingToRegenerate, regenCtx.Reason)
				if stateTransitionSucceeded {
					e.Unlock()
					e.Regenerate(owner, regenCtx)
					return nil
				}
				e.Unlock()
			case <-timeout:
				e.getLogger().Warning("timed out waiting for endpoint state to change")
				return UpdateStateChangeError{fmt.Sprintf("unable to regenerate endpoint program because state transition to %s was unsuccessful; check `cilium endpoint log %d` for more information", StateWaitingToRegenerate, e.ID)}
			}
		}

	}

	e.Unlock()
	return nil
}

// HasLabels returns whether endpoint e contains all labels l. Will return 'false'
// if any label in l is not in the endpoint's labels.
func (e *Endpoint) HasLabels(l pkgLabels.Labels) bool {
	e.UnconditionalRLock()
	defer e.RUnlock()

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

// LeaveLocked removes the endpoint's directory from the system. Must be called
// with Endpoint's mutex AND BuildMutex locked.
//
// Note: LeaveLocked() is called indirectly from endpoint restore logic for
// endpoints which failed to be restored. Any cleanup routine of LeaveLocked()
// which depends on kvstore connectivity must be protected by a flag in
// DeleteConfig and the restore logic must opt-out of it.
func (e *Endpoint) LeaveLocked(owner Owner, proxyWaitGroup *completion.WaitGroup, conf DeleteConfig) []error {
	errors := []error{}

	owner.RemoveFromEndpointQueue(uint64(e.ID))
	if e.SecurityIdentity != nil && e.realizedPolicy != nil && e.realizedPolicy.L4Policy != nil {
		// Passing a new map of nil will purge all redirects
		e.removeOldRedirects(owner, nil, proxyWaitGroup)
	}

	if e.PolicyMap != nil {
		if err := e.PolicyMap.Close(); err != nil {
			errors = append(errors, fmt.Errorf("unable to close policymap %s: %s", e.PolicyMap.String(), err))
		}
	}

	if e.bpfConfigMap != nil {
		if err := e.bpfConfigMap.Close(); err != nil {
			errors = append(errors, fmt.Errorf("unable to close configmap %s: %s", e.BPFConfigMapPath(), err))
		}
	}

	if !conf.NoIdentityRelease && e.SecurityIdentity != nil {
		identitymanager.Remove(e.SecurityIdentity)
		_, err := cache.Release(owner, context.Background(), e.SecurityIdentity)
		if err != nil {
			errors = append(errors, fmt.Errorf("unable to release identity: %s", err))
		}
		// TODO: Check if network policy was created even without SecurityIdentity
		owner.RemoveNetworkPolicy(e)
		e.SecurityIdentity = nil
	}

	e.removeDirectories()
	e.controllers.RemoveAll()
	e.cleanPolicySignals()

	if e.dnsHistoryTrigger != nil {
		e.dnsHistoryTrigger.Shutdown()
	}

	if e.ConntrackLocalLocked() {
		ctmap.CloseLocalMaps(e.ConntrackName())
	} else if !option.Config.DryMode {
		e.scrubIPsInConntrackTableLocked()
	}

	e.SetStateLocked(StateDisconnected, "Endpoint removed")

	endpointPolicyStatus.Remove(e.ID)
	e.getLogger().Info("Removed endpoint")

	return errors
}

// RegenerateWait should only be called when endpoint's state has successfully
// been changed to "waiting-to-regenerate"
func (e *Endpoint) RegenerateWait(owner Owner, reason string) error {
	if !<-e.Regenerate(owner, &ExternalRegenerationMetadata{Reason: reason}) {
		return fmt.Errorf("error while regenerating endpoint."+
			" For more info run: 'cilium endpoint get %d'", e.ID)
	}
	return nil
}

// SetContainerName modifies the endpoint's container name
func (e *Endpoint) SetContainerName(name string) {
	e.UnconditionalLock()
	e.ContainerName = name
	e.Unlock()
}

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	e.UnconditionalRLock()
	ns := e.K8sNamespace
	e.RUnlock()
	return ns
}

// SetK8sNamespace modifies the endpoint's pod name
func (e *Endpoint) SetK8sNamespace(name string) {
	e.UnconditionalLock()
	e.K8sNamespace = name
	e.UpdateLogger(map[string]interface{}{
		logfields.K8sPodName: e.GetK8sNamespaceAndPodNameLocked(),
	})
	e.Unlock()
}

// GetK8sPodName returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sPodName() string {
	e.UnconditionalRLock()
	k8sPodName := e.K8sPodName
	e.RUnlock()

	return k8sPodName
}

// HumanStringLocked returns the endpoint's most human readable identifier as string
func (e *Endpoint) HumanStringLocked() string {
	if pod := e.GetK8sNamespaceAndPodNameLocked(); pod != "" {
		return pod
	}

	return e.StringID()
}

// GetK8sNamespaceAndPodNameLocked returns the namespace and pod name.  This
// function requires e.Mutex to be held.
func (e *Endpoint) GetK8sNamespaceAndPodNameLocked() string {
	return e.K8sNamespace + "/" + e.K8sPodName
}

// SetK8sPodName modifies the endpoint's pod name
func (e *Endpoint) SetK8sPodName(name string) {
	e.UnconditionalLock()
	e.K8sPodName = name
	e.UpdateLogger(map[string]interface{}{
		logfields.K8sPodName: e.GetK8sNamespaceAndPodNameLocked(),
	})
	e.Unlock()
}

// SetContainerID modifies the endpoint's container ID
func (e *Endpoint) SetContainerID(id string) {
	e.UnconditionalLock()
	e.ContainerID = id
	e.UpdateLogger(map[string]interface{}{
		logfields.ContainerID: e.getShortContainerID(),
	})
	e.Unlock()
}

// GetContainerID returns the endpoint's container ID
func (e *Endpoint) GetContainerID() string {
	e.UnconditionalRLock()
	cID := e.ContainerID
	e.RUnlock()
	return cID
}

// GetShortContainerID returns the endpoint's shortened container ID
func (e *Endpoint) GetShortContainerID() string {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.getShortContainerID()
}

func (e *Endpoint) getShortContainerID() string {
	if e == nil {
		return ""
	}

	caplen := 10
	if len(e.ContainerID) <= caplen {
		return e.ContainerID
	}

	return e.ContainerID[:caplen]

}

// SetDockerEndpointID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerEndpointID(id string) {
	e.UnconditionalLock()
	e.DockerEndpointID = id
	e.Unlock()
}

// SetDockerNetworkID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerNetworkID(id string) {
	e.UnconditionalLock()
	e.DockerNetworkID = id
	e.Unlock()
}

// GetDockerNetworkID returns the endpoint's Docker Endpoint ID
func (e *Endpoint) GetDockerNetworkID() string {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.DockerNetworkID
}

// SetDatapathMapIDAndPinMapLocked modifies the endpoint's datapath map ID
func (e *Endpoint) SetDatapathMapIDAndPinMapLocked(id int) error {
	e.DatapathMapID = id
	return e.PinDatapathMap()
}

// IsDatapathMapPinnedLocked returns whether the endpoint's datapath map has been pinned
func (e *Endpoint) IsDatapathMapPinnedLocked() bool {
	return e.isDatapathMapPinned
}

// GetState returns the endpoint's state
// endpoint.Mutex may only be.RLockAlive()ed
func (e *Endpoint) GetStateLocked() string {
	return e.state
}

// GetState returns the endpoint's state
// endpoint.Mutex may only be.RLockAlive()ed
func (e *Endpoint) GetState() string {
	e.UnconditionalRLock()
	defer e.RUnlock()
	return e.GetStateLocked()
}

// SetStateLocked modifies the endpoint's state
// endpoint.Mutex must be held
// Returns true only if endpoints state was changed as requested
func (e *Endpoint) SetStateLocked(toState, reason string) bool {
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
		// Note that transitions to waiting-to-regenerate state
		case StateWaitingForIdentity, StateDisconnecting, StateRestoring:
			goto OKState
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
		case StateDisconnecting, StateWaitingToRegenerate, StateRestoring:
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
	// NOTE: UnconditionalLock is used here because this callback has no way of reporting an error
	e.UnconditionalLock()
	if revision > e.proxyPolicyRevision {
		e.proxyPolicyRevision = revision
	}
	e.Unlock()
}

// getProxyStatisticsLocked gets the ProxyStatistics for the flows with the
// given characteristics, or adds a new one and returns it.
// Must be called with e.proxyStatisticsMutex held.
func (e *Endpoint) getProxyStatisticsLocked(l7Protocol string, port uint16, ingress bool) *models.ProxyStatistics {
	var location string
	if ingress {
		location = models.ProxyStatisticsLocationIngress
	} else {
		location = models.ProxyStatisticsLocationEgress
	}
	key := models.ProxyStatistics{
		Location: location,
		Port:     int64(port),
		Protocol: l7Protocol,
	}

	if e.proxyStatistics == nil {
		e.proxyStatistics = make(map[models.ProxyStatistics]*models.ProxyStatistics)
	}

	proxyStats, ok := e.proxyStatistics[key]
	if !ok {
		keyCopy := key
		proxyStats = &keyCopy
		proxyStats.Statistics = &models.RequestResponseStatistics{
			Requests:  &models.MessageForwardingStatistics{},
			Responses: &models.MessageForwardingStatistics{},
		}
		e.proxyStatistics[key] = proxyStats
	}

	return proxyStats
}

// UpdateProxyStatistics updates the Endpoint's proxy  statistics to account
// for a new observed flow with the given characteristics.
func (e *Endpoint) UpdateProxyStatistics(l7Protocol string, port uint16, ingress, request bool, verdict accesslog.FlowVerdict) {
	e.proxyStatisticsMutex.Lock()
	defer e.proxyStatisticsMutex.Unlock()

	proxyStats := e.getProxyStatisticsLocked(l7Protocol, port, ingress)

	var stats *models.MessageForwardingStatistics
	if request {
		stats = proxyStats.Statistics.Requests
	} else {
		stats = proxyStats.Statistics.Responses
	}

	stats.Received++
	metrics.ProxyReceived.Inc()

	switch verdict {
	case accesslog.VerdictForwarded:
		stats.Forwarded++
		metrics.ProxyForwarded.Inc()
	case accesslog.VerdictDenied:
		stats.Denied++
		metrics.ProxyDenied.Inc()
	case accesslog.VerdictError:
		stats.Error++
		metrics.ProxyParseErrors.Inc()
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
	e.UnconditionalRLock()
	defer e.RUnlock()

	labels := ""
	if e.SecurityIdentity != nil {
		labels = e.SecurityIdentity.Labels.String()
	}

	return fmt.Sprintf("%d (%s)", e.ID, labels)
}

// ModifyIdentityLabels changes the custom and orchestration identity labels of an endpoint.
// Labels can be added or deleted. If a label change is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(owner Owner, addLabels, delLabels pkgLabels.Labels) error {
	if err := e.LockAlive(); err != nil {
		return err
	}

	switch e.GetStateLocked() {
	case StateDisconnected, StateDisconnecting:
		e.Unlock()
		return nil
	}

	changed, err := e.OpLabels.ModifyIdentityLabels(addLabels, delLabels)
	if err != nil {
		e.Unlock()
		return err
	}

	var rev int
	if changed {
		// Mark with StateWaitingForIdentity, it will be set to
		// StateWaitingToRegenerate after the identity resolution has been
		// completed
		e.SetStateLocked(StateWaitingForIdentity, "Triggering identity resolution due to updated identity labels")

		e.identityRevision++
		rev = e.identityRevision
	}
	e.Unlock()

	if changed {
		e.runLabelsResolver(context.Background(), owner, rev, false)
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
func (e *Endpoint) UpdateLabels(ctx context.Context, owner Owner, identityLabels, infoLabels pkgLabels.Labels, blocking bool) {
	log.WithFields(logrus.Fields{
		logfields.ContainerID:    e.GetShortContainerID(),
		logfields.EndpointID:     e.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	if err := e.LockAlive(); err != nil {
		e.LogDisconnectedMutexAction(err, "when trying to refresh endpoint labels")
		return
	}

	e.replaceInformationLabels(infoLabels)
	// replace identity labels and update the identity if labels have changed
	rev := e.replaceIdentityLabels(identityLabels)
	e.Unlock()
	if rev != 0 {
		e.runLabelsResolver(ctx, owner, rev, blocking)
	}
}

func (e *Endpoint) identityResolutionIsObsolete(myChangeRev int) bool {
	// If in disconnected state, skip as well as this operation is no
	// longer required.
	if e.state == StateDisconnected {
		return true
	}

	// Check if the endpoint has since received a new identity revision, if
	// so, abort as a new resolution routine will have been started.
	if myChangeRev != e.identityRevision {
		return true
	}

	return false
}

// Must be called with e.Mutex NOT held.
func (e *Endpoint) runLabelsResolver(ctx context.Context, owner Owner, myChangeRev int, blocking bool) {
	if err := e.RLockAlive(); err != nil {
		// If a labels update and an endpoint delete API request arrive
		// in quick succession, this could occur; in that case, there's
		// no point updating the controller.
		e.getLogger().WithError(err).Info("Cannot run labels resolver")
		return
	}
	newLabels := e.OpLabels.IdentityLabels()
	e.RUnlock()
	scopedLog := e.getLogger().WithField(logfields.IdentityLabels, newLabels)

	// If we are certain we can resolve the identity without accessing the KV
	// store, do it first synchronously right now. This can reduce the number
	// of regenerations for the endpoint during its initialization.
	if blocking || cache.IdentityAllocationIsLocal(newLabels) {
		scopedLog.Info("Resolving identity labels (blocking)")

		err := e.identityLabelsChanged(ctx, owner, myChangeRev)
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
				err := e.identityLabelsChanged(ctx, owner, myChangeRev)
				switch err {
				case ErrNotAlive:
					e.getLogger().Debug("not changing endpoint identity because endpoint is in process of being removed")
					return controller.NewExitReason("Endpoint disappeared")
				default:
					return err
				}
			},
			RunInterval: 5 * time.Minute,
		},
	)
}

func (e *Endpoint) identityLabelsChanged(ctx context.Context, owner Owner, myChangeRev int) error {
	if err := e.RLockAlive(); err != nil {
		return ErrNotAlive
	}
	newLabels := e.OpLabels.IdentityLabels()
	elog := e.getLogger().WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.IdentityLabels: newLabels,
	})

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.RUnlock()
		elog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return nil
	}

	if e.SecurityIdentity != nil && e.SecurityIdentity.Labels.Equals(newLabels) {
		// Sets endpoint state to ready if was waiting for identity
		if e.GetStateLocked() == StateWaitingForIdentity {
			e.SetStateLocked(StateReady, "Set identity for this endpoint")
		}
		e.RUnlock()
		elog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.RUnlock()
	elog.Debug("Resolving identity for labels")

	identity, _, err := cache.AllocateIdentity(owner, ctx, newLabels)
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
		_, err := cache.Release(owner, releaseCtx, identity)
		if err != nil {
			// non fatal error as keys will expire after lease expires but log it
			elog.WithFields(logrus.Fields{logfields.Identity: identity.ID}).
				WithError(err).Warn("Unable to release newly allocated identity again")
		}
	}

	if err := e.LockAlive(); err != nil {
		releaseNewlyAllocatedIdentity()
		return err
	}

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.Unlock()

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
		if identity.ID != oldIdentity.ID && oldIdentity.ID != identityPkg.ReservedIdentityInit {
			e.Unlock()

			elog.Debugf("Applying grace period before regeneration due to identity change")
			time.Sleep(option.Config.IdentityChangeGracePeriod)

			if err := e.LockAlive(); err != nil {
				releaseNewlyAllocatedIdentity()
				return err
			}

			// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
			if e.identityResolutionIsObsolete(myChangeRev) {
				e.Unlock()
				releaseNewlyAllocatedIdentity()
				return nil
			}
		}
	}

	elog.WithFields(logrus.Fields{logfields.Identity: identity.StringID()}).
		Debug("Assigned new identity to endpoint")

	e.SetIdentity(identity)

	if oldIdentity != nil {
		_, err := cache.Release(owner, releaseCtx, oldIdentity)
		if err != nil {
			elog.WithFields(logrus.Fields{logfields.Identity: oldIdentity.ID}).
				WithError(err).Warn("Unable to release old endpoint identity")
		}
	}

	readyToRegenerate := false

	// Regeneration is olny triggered once the endpoint ID has been
	// assigned. This ensures that on the initial creation, the endpoint is
	// not generated until the endpoint ID has been assigned. If the
	// identity is resolved before the endpoint ID is assigned, the
	// regeneration is deferred into endpointmanager.AddEndpoint(). If the
	// identity is not allocated yet when endpointmanager.AddEndpoint() is
	// called, the controller calling identityLabelsChanged() will trigger
	// the regeneration as soon as the identity is known.
	if e.ID != 0 {
		readyToRegenerate = e.SetStateLocked(StateWaitingToRegenerate, "Triggering regeneration due to new identity")
	}

	// Unconditionally force policy recomputation after a new identity has been
	// assigned.
	e.ForcePolicyCompute()

	e.Unlock()

	if readyToRegenerate {
		e.Regenerate(owner, &ExternalRegenerationMetadata{Reason: "updated security labels"})
	}

	return nil
}

// SetPolicyRevision sets the endpoint's policy revision with the given
// revision.
func (e *Endpoint) SetPolicyRevision(rev uint64) {
	if err := e.LockAlive(); err != nil {
		return
	}
	e.setPolicyRevision(rev)
	e.Unlock()
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
	// NOTE: UnconditionalLock is used here because this method handles endpoint in disconnected state on its own
	e.UnconditionalLock()
	defer e.Unlock()

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

// InsertEvent is called when the endpoint is inserted into the endpoint
// manager.
func (e *Endpoint) InsertEvent() {
	e.getLogger().Info("New endpoint")
}

// IsDisconnecting returns true if the endpoint is being disconnected or
// already disconnected
//
// This function must be called after re-aquiring the endpoint mutex to verify
// that the endpoint has not been removed in the meantime.
//
// endpoint.mutex must be held in read mode at least
func (e *Endpoint) IsDisconnecting() bool {
	return e.state == StateDisconnected || e.state == StateDisconnecting
}

// PinDatapathMap retrieves a file descriptor from the map ID from the API call
// and pins the corresponding map into the BPF file system.
func (e *Endpoint) PinDatapathMap() error {
	if e.DatapathMapID == 0 {
		return nil
	}

	mapFd, err := bpf.MapFdFromID(e.DatapathMapID)
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

func (e *Endpoint) syncEndpointHeaderFile(owner Owner, reasons []string) {
	e.BuildMutex.Lock()
	defer e.BuildMutex.Unlock()

	if err := e.LockAlive(); err != nil {
		// endpoint was removed in the meanwhile, return
		return
	}
	defer e.Unlock()

	if err := e.writeHeaderfile(e.StateDirectoryPath(), owner); err != nil {
		e.getLogger().WithFields(logrus.Fields{
			logfields.Reason: reasons,
		}).WithError(err).Warning("could not sync header file")
	}
}

// SyncEndpointHeaderFile it bumps the current DNS History information for the
// endpoint in the lxc_config.h file.
func (e *Endpoint) SyncEndpointHeaderFile(owner Owner) error {
	if err := e.LockAlive(); err != nil {
		// endpoint was removed in the meanwhile, return
		return nil
	}
	defer e.Unlock()

	if e.dnsHistoryTrigger == nil {
		t, err := trigger.NewTrigger(trigger.Parameters{
			Name:              "sync_endpoint_header_file",
			PrometheusMetrics: false,
			MinInterval:       5 * time.Second,
			TriggerFunc:       func(reasons []string) { e.syncEndpointHeaderFile(owner, reasons) },
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
