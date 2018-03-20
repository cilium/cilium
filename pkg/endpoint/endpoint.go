// Copyright 2016-2018 Authors of Cilium
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
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	go_version "github.com/hashicorp/go-version"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"context"
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
	OptionConntrackAccounting = "ConntrackAccounting"
	OptionConntrackLocal      = "ConntrackLocal"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDebugLB             = "DebugLB"
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

	OptionSpecDebugLB = option.Option{
		Define:      "LB_DEBUG",
		Description: "Enable debugging trace statements for load balancer",
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
		OptionDebugLB:             &OptionSpecDebugLB,
		OptionDropNotify:          &OptionSpecDropNotify,
		OptionTraceNotify:         &OptionSpecTraceNotify,
		OptionNAT46:               &OptionSpecNAT46,
		OptionIngressPolicy:       &OptionIngressSpecPolicy,
		OptionEgressPolicy:        &OptionEgressSpecPolicy,
	}

	EndpointOptionLibrary = option.OptionLibrary{
		OptionAllowToHost: &OptionSpecAllowToHost,
	}

	// ciliumEPControllerLimit is the range of k8s versions with which we are
	// willing to run the EndpointCRD controllers
	ciliumEPControllerLimit, _ = go_version.NewConstraint("> 1.6")

	// ciliumEndpointSyncControllerK8sClient is a k8s client shared by the
	// RunK8sCiliumEndpointSync and RunK8sCiliumEndpointSyncGC. They obtain the
	// controller via getCiliumClient and the sync.Once is used to avoid race.
	ciliumEndpointSyncControllerOnce      sync.Once
	ciliumEndpointSyncControllerK8sClient clientset.Interface
)

func init() {
	for k, v := range EndpointMutableOptionLibrary {
		EndpointOptionLibrary[k] = v
	}
}

// getCiliumClient builds and returns a k8s auto-generated client for cilium
// objects
func getCiliumClient() (ciliumClient cilium_client_v2.CiliumV2Interface, err error) {
	// This allows us to reuse the k8s client
	ciliumEndpointSyncControllerOnce.Do(func() {
		var (
			restConfig *rest.Config
			k8sClient  *clientset.Clientset
		)

		restConfig, err = k8s.CreateConfig()
		if err != nil {
			return
		}

		k8sClient, err = clientset.NewForConfig(restConfig)
		if err != nil {
			return
		}

		ciliumEndpointSyncControllerK8sClient = k8sClient
	})

	if err != nil {
		return nil, err
	}

	return ciliumEndpointSyncControllerK8sClient.CiliumV2(), nil
}

// RunK8sCiliumEndpointSyncGC starts the node-singleton sweeper for
// CiliumEndpoint objects where the managing node is no longer running. These
// objects are created by the sync-to-k8s-ciliumendpoint controller on each
// Endpoint.
// The general steps are:
//   - get list of nodes
//   - only run with probability 1/nodes
//   - get list of CEPs
//   - for each CEP
//       delete CEP if the node does not exist
// CiliumEndpoint objects follow a nodename-cep-endpointID scheme
func RunK8sCiliumEndpointSyncGC() {
	var (
		controllerName = fmt.Sprintf("sync-to-k8s-ciliumendpoint-gc (%v)", node.GetName())
		scopedLog      = log.WithField("controller", controllerName)

		// random source to throttle how often this controller runs cluster-wide
		runThrottler = rand.New(rand.NewSource(time.Now().UnixNano()))
	)

	// this is a sanity check
	if !k8s.IsEnabled() {
		scopedLog.WithField("name", controllerName).Warn("Not running controller because k8s is disabled")
		return
	}
	sv, err := k8s.GetServerVersion()
	if err != nil {
		scopedLog.WithError(err).Error("unable to retrieve kubernetes serverversion")
		return
	}
	if !ciliumEPControllerLimit.Check(sv) {
		scopedLog.WithFields(logrus.Fields{
			"expected": sv,
			"found":    ciliumEPControllerLimit,
		}).Warn("cannot run with this k8s version")
		return
	}

	ciliumClient, err := getCiliumClient()
	if err != nil {
		scopedLog.WithError(err).Error("Not starting controller because unable to get cilium k8s client")
		return
	}

	// this dummy manager is needed only to add this controller to the global list
	controller.NewManager().UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 1 * time.Minute,
			DoFunc: func() error {
				nodes := node.GetNodes()

				// Don't run if there are no other known nodes
				// Only run with a probability of 1/(number of nodes in cluster). This
				// is because this controller runs on every node on the same interval
				// but only one is neede to run.
				if len(nodes) <= 1 || runThrottler.Int63n(int64(len(nodes))) != 0 {
					return nil
				}

				// "" is all-namespaces
				ceps, err := ciliumClient.CiliumEndpoints("").List(meta_v1.ListOptions{})
				if err != nil {
					scopedLog.WithError(err).Error("Cannot list CEPs")
					return err
				}
				for _, cep := range ceps.Items {
					parts := strings.Split(cep.Name, "-cep")
					ownerNode := parts[0]

					if _, found := nodes[node.Identity{Name: ownerNode}]; !found {
						// delete
						scopedLog = scopedLog.WithFields(logrus.Fields{
							logfields.EndpointID: cep.Status.ID,
							logfields.Node:       ownerNode,
						})
						scopedLog.Info("Orphaned CiliumEndpoint is being garbage collected")
						if err := ciliumClient.CiliumEndpoints(cep.Namespace).Delete(cep.Name, &meta_v1.DeleteOptions{}); err != nil {
							scopedLog.WithError(err).Error("Unable to delete CEP")
							return err
						}
					}
				}
				return nil
			},
		})
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

	// ReservedEPNamespace is the namespace to use for reserved endpoints that
	// don't have a namespace (e.g. health)
	ReservedEPNamespace = "kube-system"
)

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

	// LabelsHash is a SHA256 hash over the SecurityIdentity labels
	LabelsHash string

	// LabelsMap is the Set of all security labels used in the last policy computation
	LabelsMap *identityPkg.IdentityCache

	// PortMap is port mapping configuration of the endpoint
	PortMap []PortMap // Port mapping used for this endpoint.

	// Consumable represents the security-identity-based policy for this endpoint.
	Consumable *policy.Consumable `json:"-"`

	// L4Policy is the L4Policy in effect for the
	// endpoint. Outside of policy recalculation, it is the same as the
	// Consumable's L4Policy, but this is needed during policy recalculation to
	// be able to clean up PolicyMap after the endpoint's consumable has already
	// been updated.
	L4Policy *policy.L4Policy `json:"-"`

	// PolicyMap is the policy related state of the datapath including
	// reference to all policy related BPF
	PolicyMap *policymap.PolicyMap `json:"-"`

	// CIDRPolicy is the CIDR based policy configuration of the endpoint. This
	// is not contained within the Consumable for this endpoint because the
	// Consumable only contains identity-based policy information.
	L3Policy *policy.CIDRPolicy `json:"-"`

	// L3Maps is the datapath representation of CIDRPolicy
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

	k8sPodName   string
	k8sNamespace string

	// policyRevision is the policy revision this endpoint is currently on
	// to modify this field please use endpoint.setPolicyRevision instead
	policyRevision uint64
	// policyRevisionSignals contains a map of PolicyRevision signals that
	// should be triggered once the policyRevision reaches the wanted wantedRev.
	policyRevisionSignals map[policySignal]bool

	// proxyPolicyRevision is the policy revision that has been applied to
	// the proxy.
	proxyPolicyRevision uint64

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

	// controllers is the list of async controllers syncing the endpoint to
	// other resources
	controllers controller.Manager

	// realizedRedirects maps the ID of each proxy redirect that has been
	// successfully added into a proxy for this endpoint, to the redirect's
	// proxy port number.
	// You must hold Endpoint.Mutex to read or write it.
	realizedRedirects map[string]uint16

	// ProxyWaitGroup waits for pending proxy changes to complete.
	// You must hold Endpoint.BuildMutex to read or write it.
	ProxyWaitGroup *completion.WaitGroup `json:"-"`
}

// WaitForProxyCompletions blocks until all proxy changes have been completed.
// Called with BuildMutex held.
func (e *Endpoint) WaitForProxyCompletions() error {
	start := time.Now()
	e.getLogger().Debug("Waiting for proxy updates to complete...")
	err := e.ProxyWaitGroup.Wait()
	if err != nil {
		return fmt.Errorf("proxy state changes failed: %s", err)
	}
	e.getLogger().Debug("Wait time for proxy updates: ", time.Since(start))
	return nil
}

// RunK8sCiliumEndpointSync starts a controller that syncronizes the endpoint
// to the corresponding k8s CiliumEndpoint CRD
// CiliumEndpoint objects follow a nodename-cep-endpointID scheme
func (e *Endpoint) RunK8sCiliumEndpointSync() {
	var (
		endpointID     = e.ID
		controllerName = fmt.Sprintf("sync-to-k8s-ciliumendpoint (%v)", endpointID)
		epName         = fmt.Sprintf("%v-cep-%v", node.GetName(), endpointID)
		scopedLog      = e.getLogger().WithField("controller", controllerName)
	)

	if !k8s.IsEnabled() {
		scopedLog.Debug("Not starting controller because k8s is disabled")
		return
	}
	sv, err := k8s.GetServerVersion()
	if err != nil {
		scopedLog.WithError(err).Error("unable to retrieve kubernetes serverversion")
		return
	}
	if !ciliumEPControllerLimit.Check(sv) {
		scopedLog.WithFields(logrus.Fields{
			"expected": sv,
			"found":    ciliumEPControllerLimit,
		}).Warn("cannot run with this k8s version")
		return
	}

	ciliumClient, err := getCiliumClient()
	if err != nil {
		scopedLog.WithError(err).Error("Not starting controller because unable to get cilium k8s client")
		return
	}

	var lastMdl *models.Endpoint

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.controllers.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 10 * time.Second,
			DoFunc: func() (err error) {
				namespace := e.GetK8sNamespace()
				if namespace == "" {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s namespace")
					return nil
				}

				mdl := e.GetModel()
				if reflect.DeepEqual(mdl, lastMdl) {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has not changed")
					return nil
				}
				defer func() {
					if err == nil {
						lastMdl = mdl
					}
				}()

				cep, err := ciliumClient.CiliumEndpoints(namespace).Get(epName, meta_v1.GetOptions{})
				switch {
				// A real error
				case err != nil && !k8serrors.IsNotFound(err):
					scopedLog.WithError(err).Error("Cannot get CEP for update")
					return err

				// do an update
				case err == nil:
					// Update the copy of the cep
					(*cilium_v2.CiliumEndpointDetail)(mdl).DeepCopyInto(&cep.Status)
					if cep.Status.ID == 0 {
						err = errors.New("Failed to deepcopy CiliumEndpoint object")
						scopedLog.WithError(err).Error("Cannot deepcopy CEP.status")
						return err
					}

					if _, err = ciliumClient.CiliumEndpoints(namespace).Update(cep); err != nil {
						scopedLog.WithError(err).Error("Cannot update CEP")
						return err
					}

					return nil
				}

				// The CEP was not found, this is the first creation of the endpoint
				cep = &cilium_v2.CiliumEndpoint{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: epName,
					},
					Status: cilium_v2.CiliumEndpointDetail(*mdl),
				}

				_, err = ciliumClient.CiliumEndpoints(namespace).Create(cep)
				if err != nil {
					scopedLog.WithError(err).Error("Cannot create CEP")
					return err
				}

				return nil
			},
			StopFunc: func() error {
				namespace := e.GetK8sNamespace()
				if err := ciliumClient.CiliumEndpoints(namespace).Delete(epName, &meta_v1.DeleteOptions{}); err != nil {
					scopedLog.WithError(err).Error("Unable to delete CEP")
					return err
				}
				return nil
			},
		})
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

	mdl := &models.Endpoint{
		ID:               int64(e.ID),
		Configuration:    e.Opts.GetModel(),
		ContainerID:      e.DockerID,
		ContainerName:    e.ContainerName,
		DockerEndpointID: e.DockerEndpointID,
		DockerNetworkID:  e.DockerNetworkID,
		Identity:         e.SecurityIdentity.GetModel(),
		InterfaceIndex:   int64(e.IfIndex),
		InterfaceName:    e.IfName,
		Labels: &models.LabelConfiguration{
			Custom:                e.OpLabels.Custom.GetModel(),
			OrchestrationIdentity: e.OpLabels.OrchestrationIdentity.GetModel(),
			OrchestrationInfo:     e.OpLabels.OrchestrationInfo.GetModel(),
			Disabled:              e.OpLabels.Disabled.GetModel(),
		},
		Mac:                 e.LXCMAC.String(),
		HostMac:             e.NodeMAC.String(),
		PodName:             e.GetK8sNamespaceAndPodNameLocked(),
		State:               currentState, // TODO: Validate
		Status:              statusLog,
		Health:              e.getHealthModel(),
		Policy:              e.GetPolicyModel(),
		PolicyEnabled:       &policy,
		PolicyRevision:      int64(e.policyRevision),
		ProxyPolicyRevision: int64(e.proxyPolicyRevision),
		Addressing: &models.EndpointAddressing{
			IPV4: e.IPv4.String(),
			IPV6: e.IPv6.String(),
		},
		Controllers: e.controllers.GetStatusModel(),
	}

	// Sort these slices since they come out in random orders. This allows
	// reflect.DeepEqual to succeed.
	sort.StringSlice(mdl.Labels.Custom).Sort()
	sort.StringSlice(mdl.Labels.Disabled).Sort()
	sort.StringSlice(mdl.Labels.OrchestrationIdentity).Sort()
	sort.StringSlice(mdl.Labels.OrchestrationInfo).Sort()
	sort.Slice(mdl.Controllers, func(i, j int) bool { return mdl.Controllers[i].Name < mdl.Controllers[j].Name })
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

	ingressIdentities := make([]int64, 0, len(e.Consumable.IngressIdentities))
	for ingressIdentity := range e.Consumable.IngressIdentities {
		ingressIdentities = append(ingressIdentities, int64(ingressIdentity))
	}

	return &models.EndpointPolicy{
		ID:    int64(e.Consumable.ID),
		Build: int64(e.Consumable.Iteration),
		AllowedIngressIdentities: ingressIdentities,
		CidrPolicy:               e.L3Policy.GetModel(),
		L4:                       e.Consumable.L4Policy.GetModel(),
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
	if e.SecurityIdentity == nil {
		return []string{}
	}

	return e.SecurityIdentity.Labels.GetModel()
}

// GetLabelsSHA returns the SHA of labels
func (e *Endpoint) GetLabelsSHA() string {
	if e.SecurityIdentity == nil {
		return ""
	}

	return e.SecurityIdentity.GetLabelsSHA256()
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

func (e *Endpoint) GetIdentity() identityPkg.NumericIdentity {
	if e.SecurityIdentity != nil {
		return e.SecurityIdentity.ID
	}

	return identityPkg.InvalidIdentity
}

func (e *Endpoint) directoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d", e.ID))
}

func (e *Endpoint) Allows(id identityPkg.NumericIdentity) bool {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()
	if e.Consumable != nil {
		return e.Consumable.AllowsIngress(id)
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

	// We need to check for nil in Status, CurrentStatuses and Log, since in
	// some use cases, status will be not nil and Cilium will eventually
	// error/panic if CurrentStatus or Log are not initialized correctly.
	// Reference issue GH-2477
	if ep.Status == nil || ep.Status.CurrentStatuses == nil || ep.Status.Log == nil {
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
		gpm.DeleteIdentity(uint32(e.ID), policymap.Ingress)
		gpm.DeleteIdentity(uint32(e.ID), policymap.Egress)
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
		// Store security identity in network byte order so it can be
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

// PolicyMapPathLocked returns the path to the policy map of endpoint.
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
	// FIXME GH2323 instead of a mutex we could use a channel to send the status
	// log message to a single writer?
	e.Status.indexMU.Lock()
	defer e.Status.indexMU.Unlock()
	e.logStatusLocked(typ, code, msg)
}

func (e *Endpoint) LogStatusOK(typ StatusType, msg string) {
	e.LogStatus(typ, OK, msg)
}

// LogStatusOKLocked will log an OK message of the given status type with the
// given msg string.
// must be called with endpoint.Mutex held
func (e *Endpoint) LogStatusOKLocked(typ StatusType, msg string) {
	e.Status.indexMU.Lock()
	defer e.Status.indexMU.Unlock()
	e.logStatusLocked(typ, OK, msg)
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

// Update modifies the endpoint options and *always* tries to regenerate the
// endpoint's program.
func (e *Endpoint) Update(owner Owner, opts models.ConfigurationMap) error {
	e.Mutex.Lock()
	if err := e.Opts.Validate(opts); err != nil {
		e.Mutex.Unlock()
		return UpdateValidationError{err.Error()}
	}

	// Option changes may be overridden by the policy configuration.
	// Currently we return all-OK even in that case.
	needToRegenerate, ctCleaned, err := e.TriggerPolicyUpdatesLocked(owner, opts)
	if err != nil {
		e.Mutex.Unlock()
		ctCleaned.Wait()
		return UpdateCompilationError{err.Error()}
	}

	reason := "endpoint was updated via API"

	// If configuration options are provided, we only regenerate if necessary.
	// Otherwise always regenerate.
	if opts == nil {
		needToRegenerate = true
		reason = "endpoint was manually regenerated via API"
	}

	if needToRegenerate {
		stateTransitionSucceeded := e.SetStateLocked(StateWaitingToRegenerate, reason)

		e.Mutex.Unlock()
		ctCleaned.Wait()

		if stateTransitionSucceeded {
			e.Regenerate(owner, reason)
			return nil
		}

		// FIXME: GH-3058: We need to queue up a regeneration
		// nevertheless
		return nil
	}

	e.Mutex.Unlock()
	ctCleaned.Wait()

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

func (e *Endpoint) replaceInformationLabels(l pkgLabels.Labels) {
	e.Mutex.Lock()
	for k, v := range l {
		tmp := v.DeepCopy()
		e.getLogger().WithField(logfields.Labels, logfields.Repr(tmp)).Debug("Assigning orchestration information label")
		e.OpLabels.OrchestrationInfo[k] = tmp
	}
	e.Mutex.Unlock()
}

// replaceIdentityLabels replaces the identity labels of an endpoint. If a net
// changed occurred, the identityRevision is bumped and return, otherwise 0 is
// returned.
func (e *Endpoint) replaceIdentityLabels(l pkgLabels.Labels) int {
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

	rev := 0
	if changed {
		e.identityRevision++
		rev = e.identityRevision
	}

	e.Mutex.Unlock()

	return rev
}

// LeaveLocked removes the endpoint's directory from the system. Must be called
// with Endpoint's mutex AND BuildMutex locked.
func (e *Endpoint) LeaveLocked(owner Owner) int {
	errors := 0

	owner.RemoveFromEndpointQueue(uint64(e.ID))
	if c := e.Consumable; c != nil {
		c.Mutex.Lock()
		if e.L4Policy != nil {
			// Passing a new map of nil will purge all redirects
			e.removeOldRedirects(owner, nil)
		}
		c.Mutex.Unlock()
	}

	if e.PolicyMap != nil {
		if err := e.PolicyMap.Close(); err != nil {
			e.getLogger().WithError(err).WithField(logfields.Path, e.PolicyMapPathLocked()).Warn("Unable to close policy map")
			errors++
		}
	}

	if e.SecurityIdentity != nil {
		err := e.SecurityIdentity.Release()
		if err != nil {
			log.WithError(err).WithField(logfields.Identity, e.SecurityIdentity.ID).
				Error("Unable to release identity of endpoint")
			errors++
		}
		// TODO: Check if network policy was created even without SecurityIdentity
		owner.RemoveNetworkPolicy(e)
		e.SecurityIdentity = nil
	}

	e.L3Maps.Close()
	e.removeDirectory()
	e.controllers.RemoveAll()
	e.cleanPolicySignals()

	e.SetStateLocked(StateDisconnected, "Endpoint removed")

	return errors
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

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	return e.k8sNamespace
}

// SetK8sNamespace modifies the endpoint's pod name
func (e *Endpoint) SetK8sNamespace(name string) {
	e.Mutex.Lock()
	e.k8sNamespace = name
	e.Mutex.Unlock()
}

// GetK8sPodName returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sPodName() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	return e.k8sPodName
}

// GetK8sNamespaceAndPodNameLocked returns the namespace and pod name.  This
// function requires e.Mutex to be held.
func (e *Endpoint) GetK8sNamespaceAndPodNameLocked() string {
	return e.k8sNamespace + ":" + e.k8sPodName
}

// SetK8sPodName modifies the endpoint's pod name
func (e *Endpoint) SetK8sPodName(name string) {
	e.Mutex.Lock()
	e.k8sPodName = name
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
	e.Mutex.RLock()
	id := e.getShortContainerID()
	e.Mutex.RUnlock()
	return id
}

func (e *Endpoint) getShortContainerID() string {
	if e == nil {
		return ""
	}

	caplen := 10
	if len(e.DockerID) <= caplen {
		return e.DockerID
	}

	return e.DockerID[:caplen]

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
		case StateDisconnecting, StateWaitingToRegenerate:
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
		e.setPolicyRevision(revision)
	}
	e.Mutex.Unlock()
}

// OnProxyPolicyUpdate is a callback used to update the Endpoint's
// proxyPolicyRevision when the specified revision has been applied in the
// proxy.
func (e *Endpoint) OnProxyPolicyUpdate(revision uint64) {
	e.Mutex.Lock()
	if revision > e.proxyPolicyRevision {
		e.proxyPolicyRevision = revision
	}
	e.Mutex.Unlock()
}

// APICanModify determines whether API requests from a user are allowed to
// modify this endpoint.
func APICanModify(e *Endpoint) error {
	if lbls := e.OpLabels.OrchestrationIdentity.FindReserved(); lbls != nil {
		return fmt.Errorf("Endpoint cannot be modified by API call")
	}
	return nil
}

func (e *Endpoint) getIDandLabels() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	labels := ""
	if e.SecurityIdentity != nil {
		labels = e.SecurityIdentity.Labels.String()
	}

	return fmt.Sprintf("%d (%s)", e.ID, labels)
}

// ModifyIdentityLabels changes the identity relevant labels of an endpoint.
// labels can be added or deleted. If a net label changed is performed, the
// endpoint will receive a new identity and will be regenerated. Both of these
// operations will happen in the background.
func (e *Endpoint) ModifyIdentityLabels(owner Owner, addLabels, delLabels labels.Labels) error {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	newLabels := e.OpLabels.DeepCopy()

	if len(delLabels) > 0 {
		for k := range delLabels {
			// The change request is accepted if the label is on
			// any of the lists. If the label is already disabled,
			// we will simply ignore that change.
			if newLabels.OrchestrationIdentity[k] != nil ||
				newLabels.Custom[k] != nil ||
				newLabels.Disabled[k] != nil {
				break
			}

			return fmt.Errorf("label %s not found", k)
		}
	}

	if len(delLabels) > 0 {
		for k, v := range delLabels {
			if newLabels.OrchestrationIdentity[k] != nil {
				delete(newLabels.OrchestrationIdentity, k)
				newLabels.Disabled[k] = v
			}

			if newLabels.Custom[k] != nil {
				delete(newLabels.Custom, k)
			}
		}
	}

	if len(addLabels) > 0 {
		for k, v := range addLabels {
			if newLabels.Disabled[k] != nil {
				delete(newLabels.Disabled, k)
				newLabels.OrchestrationIdentity[k] = v
			} else if newLabels.OrchestrationIdentity[k] == nil {
				newLabels.Custom[k] = v
			}
		}
	}

	e.OpLabels = *newLabels

	// Mark with StateWaitingForIdentity, it will be set to
	// StateWaitingToRegenerate after the identity resolution has been
	// completed
	e.SetStateLocked(StateWaitingForIdentity, "Triggering identity resolution due to updated security labels")

	e.identityRevision++
	rev := e.identityRevision

	e.runLabelsResolver(owner, rev)

	return nil
}

// UpdateLabels is called to update the labels of an endpoint. Calls to this
// function do not necessarily mean that the labels actually changed. The
// container runtime layer will periodically synchronize labels.
//
// If a net label changed was performed, the endpoint will receive a new
// identity and will be regenerated. Both of these operations will happen in
// the background.
func (e *Endpoint) UpdateLabels(owner Owner, identityLabels, infoLabels labels.Labels) {
	log.WithFields(logrus.Fields{
		logfields.ContainerID:    e.GetShortContainerID(),
		logfields.EndpointID:     e.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	e.replaceInformationLabels(infoLabels)

	// replace identity labels and update the identity if labels have changed
	if rev := e.replaceIdentityLabels(identityLabels); rev != 0 {
		e.runLabelsResolver(owner, rev)
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

func (e *Endpoint) runLabelsResolver(owner Owner, myChangeRev int) {
	ctrlName := fmt.Sprintf("resolve-identity-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func() error {
				return e.identityLabelsChanged(owner, myChangeRev)
			},
			RunInterval: time.Duration(5) * time.Minute,
		},
	)
}

func (e *Endpoint) identityLabelsChanged(owner Owner, myChangeRev int) error {
	e.Mutex.RLock()
	newLabels := e.OpLabels.IdentityLabels()
	elog := log.WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.IdentityLabels: newLabels,
	})

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.Mutex.RUnlock()
		elog.Debug("Endpoint identity has changed, aborting resolution routine in favour of new one")
		return nil
	}

	if e.SecurityIdentity != nil &&
		string(e.SecurityIdentity.Labels.SortedList()) == string(newLabels.SortedList()) {

		e.Mutex.RUnlock()
		elog.Debug("Endpoint labels unchanged, skipping resolution of identity")
		return nil
	}

	// Unlock the endpoint mutex for the possibly long lasting kvstore operation
	e.Mutex.RUnlock()
	elog.Debug("Resolving identity for labels")

	identity, _, err := identityPkg.AllocateIdentity(newLabels)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %s", err)
		e.LogStatus(Other, Warning, fmt.Sprintf("%s (will retry)", err.Error()))
		return err
	}

	e.Mutex.Lock()

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.Mutex.Unlock()

		err := identity.Release()
		if err != nil {
			// non fatal error as keys will expire after lease expires but log it
			elog.WithFields(logrus.Fields{logfields.Identity: identity.ID}).
				WithError(err).Warn("Unable to release newly allocated identity again")
		}

		return nil
	}

	// If endpoint has an old identity, defer release of it to the end of
	// the function after the endpoint structured has been unlocked again
	if e.SecurityIdentity != nil {
		oldIdentity := e.SecurityIdentity
		defer func() {
			err := oldIdentity.Release()
			if err != nil {
				elog.WithFields(logrus.Fields{logfields.Identity: oldIdentity.ID}).
					WithError(err).Warn("BUG: Unable to release old endpoint identity")
			}
		}()
	}

	elog.WithFields(logrus.Fields{logfields.Identity: identity.StringID()}).
		Debug("Assigned new identity to endpoint")

	e.SetIdentity(owner, identity)

	ready := e.SetStateLocked(StateWaitingToRegenerate, "Triggering regeneration due to new identity")
	if ready {
		e.ForcePolicyCompute()
	}

	e.Mutex.Unlock()

	if ready {
		e.Regenerate(owner, "updated security labels")
	}

	return nil
}

// setPolicyRevision sets the policy wantedRev with the given revision.
func (e *Endpoint) setPolicyRevision(rev uint64) {
	e.policyRevision = rev
	for ps := range e.policyRevisionSignals {
		select {
		case <-ps.ctx.Done():
			close(ps.ch)
			delete(e.policyRevisionSignals, ps)
		default:
			if rev >= ps.wantedRev {
				close(ps.ch)
				delete(e.policyRevisionSignals, ps)
			}
		}
	}
}

// cleanPolicySignals closes and removes all policy revision signals.
func (e *Endpoint) cleanPolicySignals() {
	for w := range e.policyRevisionSignals {
		close(w.ch)
	}
	e.policyRevisionSignals = map[policySignal]bool{}
}

// policySignal is used to mark when a wanted policy wantedRev is reached
type policySignal struct {
	// wantedRev specifies which policy revision the signal wants.
	wantedRev uint64
	// ch is the channel that signalizes once the policy revision wanted is reached.
	ch chan struct{}
	// ctx is the context for the policy signal request.
	ctx context.Context
}

// WaitForPolicyRevision returns a channel that is closed when one or more of
// the following conditions have met:
//  - the endpoint is disconnected state
//  - the endpoint's policy revision reaches the wanted revision
func (e *Endpoint) WaitForPolicyRevision(ctx context.Context, rev uint64) <-chan struct{} {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	ch := make(chan struct{})
	if e.policyRevision >= rev || e.state == StateDisconnected {
		close(ch)
		return ch
	}
	ps := policySignal{
		wantedRev: rev,
		ctx:       ctx,
		ch:        ch,
	}
	if e.policyRevisionSignals == nil {
		e.policyRevisionSignals = map[policySignal]bool{}
	}
	e.policyRevisionSignals[ps] = true
	return ch
}
