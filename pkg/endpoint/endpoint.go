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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
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
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor/notifications"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/hashicorp/go-version"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/sirupsen/logrus"
)

const (
	maxLogs = 256
)

var (
	EndpointMutableOptionLibrary = option.GetEndpointMutableOptionLibrary()

	// ciliumEPControllerLimit is the range of k8s versions with which we are
	// willing to run the EndpointCRD controllers
	ciliumEPControllerLimit = versioncheck.MustCompile("> 1.6")

	// ciliumEndpointSyncControllerK8sClient is a k8s client shared by the
	// RunK8sCiliumEndpointSync and RunK8sCiliumEndpointSyncGC. They obtain the
	// controller via getCiliumClient and the sync.Once is used to avoid race.
	ciliumEndpointSyncControllerOnce      sync.Once
	ciliumEndpointSyncControllerK8sClient clientset.Interface

	// ciliumUpdateStatusVerConstr is the minimal version supported for
	// to perform a CRD UpdateStatus.
	ciliumUpdateStatusVerConstr = versioncheck.MustCompile(">= 1.11.0")

	k8sServerVer *go_version.Version
)

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

	// This guards against the situation where another invocation of this
	// function (in another thread or previous in time) might have returned an
	// error and not initialized ciliumEndpointSyncControllerK8sClient
	if ciliumEndpointSyncControllerK8sClient == nil {
		return nil, errors.New("No initialised k8s Cilium CRD client")
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
//       delete CEP if the corresponding pod does not exist
// CiliumEndpoint objects have the same name as the pod they represent
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
	k8sClient := k8s.Client()

	// this dummy manager is needed only to add this controller to the global list
	controller.NewManager().UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 1 * time.Minute,
			DoFunc: func() error {
				// Don't run if there are no other known nodes
				// Only run with a probability of 1/(number of nodes in cluster). This
				// is because this controller runs on every node on the same interval
				// but only one is neede to run.
				nodes := node.GetNodes()
				if len(nodes) <= 1 || runThrottler.Int63n(int64(len(nodes))) != 0 {
					return nil
				}

				clusterPodSet := map[string]bool{}
				clusterPods, err := k8sClient.CoreV1().Pods("").List(meta_v1.ListOptions{})
				if err != nil {
					return err
				}
				for _, pod := range clusterPods.Items {
					podFullName := pod.Name + ":" + pod.Namespace
					clusterPodSet[podFullName] = true
				}

				// "" is all-namespaces
				ceps, err := ciliumClient.CiliumEndpoints(meta_v1.NamespaceAll).List(meta_v1.ListOptions{})
				if err != nil {
					scopedLog.WithError(err).Debug("Cannot list CEPs")
					return err
				}
				for _, cep := range ceps.Items {
					cepFullName := cep.Name + ":" + cep.Namespace
					if _, found := clusterPodSet[cepFullName]; !found {
						// delete
						scopedLog = scopedLog.WithFields(logrus.Fields{
							logfields.EndpointID: cep.Status.ID,
							logfields.K8sPodName: cepFullName,
						})
						scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")
						if err := ciliumClient.CiliumEndpoints(cep.Namespace).Delete(cep.Name, &meta_v1.DeleteOptions{}); err != nil {
							scopedLog.WithError(err).Debug("Unable to delete CEP")
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

	// HealthCEPPrefix is the prefix used to name the cilium health endpoints' CEP
	HealthCEPPrefix = "cilium-health-"
)

// compile time interface check
var _ notifications.RegenNotificationInfo = &Endpoint{}

// PolicyMapState is a state of a policy map.
type PolicyMapState map[policymap.PolicyKey]PolicyMapStateEntry

// PolicyMapStateEntry is the configuration associated with a PolicyKey in a
// PolicyMapState. This is a minimized version of policymap.PolicyEntry.
type PolicyMapStateEntry struct {
	// The proxy port, in host byte order.
	// If 0 (default), there is no proxy redirection for the corresponding
	// PolicyKey.
	ProxyPort uint16
}

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

	// DockerID is the container ID that docker has assigned to the endpoint
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

	// hasSidecarProxy indicates whether the endpoint has been injected by
	// Istio with a Cilium-compatible sidecar proxy. If true, the sidecar proxy
	// will be used to apply L7 policy rules. Otherwise, Cilium's node-wide
	// proxy will be used.
	// TODO: Currently this applies only to HTTP L7 rules. Kafka L7 rules are still enforced by Cilium's node-wide Kafka proxy.
	hasSidecarProxy bool

	// prevIdentityCache is the set of all security identities used in the
	// previous policy computation
	prevIdentityCache *identityPkg.IdentityCache

	// Iteration policy of the Endpoint
	// TODO: update documentation; description is not clear, and needs to be
	// more specific.
	Iteration uint64 `json:"-"`

	// RealizedL4Policy is the L4Policy in effect for the endpoint.
	RealizedL4Policy *policy.L4Policy `json:"-"`

	// DesiredL4Policy is the desired L4Policy for the endpoint. It is populated
	// when the policy for this endpoint is generated.
	DesiredL4Policy *policy.L4Policy `json:"-"`

	// PolicyMap is the policy related state of the datapath including
	// reference to all policy related BPF
	PolicyMap *policymap.PolicyMap `json:"-"`

	// CIDRPolicy is the CIDR based policy configuration of the endpoint.
	L3Policy *policy.CIDRPolicy `json:"-"`

	// Options determine the datapath configuration of the endpoint.
	Options *option.IntOptions

	// Status are the last n state transitions this endpoint went through
	Status *EndpointStatus

	// state is the state the endpoint is in. See SetStateLocked()
	state string

	// PolicyCalculated is true as soon as the policy has been calculated
	// for the first time. As long as this value is false, all packets sent
	// by the endpoint will be dropped to ensure that the endpoint cannot
	// bypass policy while it is still being resolved.
	PolicyCalculated bool `json:"-"`

	// bpfHeaderfileHash is the hash of the last BPF headerfile that has been
	// compiled and installed.
	bpfHeaderfileHash string

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
	logger *logrus.Entry

	// loggerMutex protects write operations to the logger field.
	//
	// NOTE: If both endpoint.Mutex and endpoint.loggerMutex must be held,
	// then endpoint.Mutex must *always* be acquired first.
	loggerMutex lock.RWMutex

	// controllers is the list of async controllers syncing the endpoint to
	// other resources
	controllers controller.Manager

	// realizedRedirects maps the ID of each proxy redirect that has been
	// successfully added into a proxy for this endpoint, to the redirect's
	// proxy port number.
	// You must hold Endpoint.Mutex to read or write it.
	realizedRedirects map[string]uint16

	// realizedMapState maps each PolicyKey which is presently
	// inserted (realized) in the endpoint's BPF PolicyMap to a proxy port.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the PolicyKey and the proxy port must be in host byte-order.
	realizedMapState PolicyMapState

	// desiredMapState maps each PolicyKeys which should be synched
	// with, but may not yet be synched with, the endpoint's BPF PolicyMap, to
	// a proxy port.
	// This map is updated upon regeneration of policy for an endpoint.
	// Proxy port 0 indicates no proxy redirection.
	// All fields within the PolicyKey and the proxy port must be in host byte-order.
	desiredMapState PolicyMapState

	// ctCleaned indicates whether the conntrack table has already been
	// cleaned when this endpoint was first created
	ctCleaned bool

	///////////////////////
	// DEPRECATED FIELDS //
	///////////////////////

	// DeprecatedOpts represents the mutable options for the endpoint, in
	// the format understood by Cilium 1.1 or earlier.
	//
	// Deprecated: Use Options instead.
	DeprecatedOpts deprecatedOptions `json:"Opts"`
}

// WaitForProxyCompletions blocks until all proxy changes have been completed.
// Called with BuildMutex held.
func (e *Endpoint) WaitForProxyCompletions(proxyWaitGroup *completion.WaitGroup) error {
	if proxyWaitGroup == nil {
		return nil
	}

	start := time.Now()

	if err := e.RLockAlive(); err != nil {
		return err
	}
	logger := e.getLogger()
	e.RUnlock()

	logger.Debug("Waiting for proxy updates to complete...")

	err := proxyWaitGroup.Wait()
	if err != nil {
		return fmt.Errorf("proxy state changes failed: %s", err)
	}
	logger.Debug("Wait time for proxy updates: ", time.Since(start))

	return nil
}

// RunK8sCiliumEndpointSync starts a controller that syncronizes the endpoint
// to the corresponding k8s CiliumEndpoint CRD
// CiliumEndpoint objects have the same name as the pod they represent
//
// Endpoint.Mutex must be RLocked. This is guaranteed via
// endpointmanager.Insert() but is really not ideal.
func (e *Endpoint) RunK8sCiliumEndpointSync() {
	var (
		endpointID     = e.ID
		controllerName = fmt.Sprintf("sync-to-k8s-ciliumendpoint (%v)", endpointID)
		scopedLog      = e.getLogger().WithField("controller", controllerName)
		err            error
	)

	if !k8s.IsEnabled() {
		scopedLog.Debug("Not starting controller because k8s is disabled")
		return
	}
	k8sServerVer, err = k8s.GetServerVersion()
	if err != nil {
		scopedLog.WithError(err).Error("unable to retrieve kubernetes serverversion")
		return
	}
	if !ciliumEPControllerLimit.Check(k8sServerVer) {
		scopedLog.WithFields(logrus.Fields{
			"expected": k8sServerVer,
			"found":    ciliumEPControllerLimit,
		}).Warn("cannot run with this k8s version")
		return
	}

	ciliumClient, err := getCiliumClient()
	if err != nil {
		scopedLog.WithError(err).Error("Not starting controller because unable to get cilium k8s client")
		return
	}

	// The health endpoint doesn't really exist in k8s and updates to it caused
	// arbitrary errors. Disable the controller for these endpoints.
	if isHealthEP := e.hasLabelsRLocked(pkgLabels.LabelHealth); isHealthEP {
		scopedLog.Debug("Not starting unnecessary CEP controller for cilium-health endpoint")
		return
	}

	var (
		lastMdl  *models.Endpoint
		firstRun = true
	)

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.controllers.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 10 * time.Second,
			DoFunc: func() (err error) {
				e.UnconditionalLock()
				// Update logger as scopeLog might not have the podName when it
				// was created.
				scopedLog = e.getLogger().WithField("controller", controllerName)
				e.Unlock()

				podName := e.GetK8sPodName()
				if podName == "" {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s pod name")
					return nil
				}

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
				k8sMdl := (*cilium_v2.CiliumEndpointDetail)(mdl)

				cep, err := ciliumClient.CiliumEndpoints(namespace).Get(podName, meta_v1.GetOptions{})
				switch {
				// The CEP doesn't exist. We will fall through to the create code below
				case err != nil && k8serrors.IsNotFound(err):
					break

				// Delete the CEP on the first ever run. We will fall through to the create code below
				case firstRun:
					firstRun = false
					scopedLog.Debug("Deleting CEP on first run")
					err := ciliumClient.CiliumEndpoints(namespace).Delete(podName, &meta_v1.DeleteOptions{})
					if err != nil {
						scopedLog.WithError(err).Warn("Error deleting CEP")
						return err
					}

				// Delete an invalid CEP. We will fall through to the create code below
				case err != nil && k8serrors.IsInvalid(err):
					scopedLog.WithError(err).Warn("Invalid CEP during update")
					err := ciliumClient.CiliumEndpoints(namespace).Delete(podName, &meta_v1.DeleteOptions{})
					if err != nil {
						scopedLog.WithError(err).Warn("Error deleting invalid CEP during update")
						return err
					}

				// A real error
				case err != nil && !k8serrors.IsNotFound(err):
					scopedLog.WithError(err).Error("Cannot get CEP for update")
					return err

				// do an update
				case err == nil:
					// Update the copy of the cep
					k8sMdl.DeepCopyInto(&cep.Status)
					var err2 error
					switch {
					case ciliumUpdateStatusVerConstr.Check(k8sServerVer):
						_, err2 = ciliumClient.CiliumEndpoints(namespace).UpdateStatus(cep)
					default:
						_, err2 = ciliumClient.CiliumEndpoints(namespace).Update(cep)
					}
					if err2 != nil {
						scopedLog.WithError(err2).Error("Cannot update CEP")
						return err2
					}

					lastMdl = mdl
					return nil
				}

				// The CEP was not found, this is the first creation of the endpoint
				cep = &cilium_v2.CiliumEndpoint{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: podName,
					},
					Status: *k8sMdl,
				}

				_, err = ciliumClient.CiliumEndpoints(namespace).Create(cep)
				if err != nil {
					scopedLog.WithError(err).Error("Cannot create CEP")
					return err
				}

				return nil
			},
			StopFunc: func() error {
				podName := e.GetK8sPodName()
				namespace := e.GetK8sNamespace()
				if err := ciliumClient.CiliumEndpoints(namespace).Delete(podName, &meta_v1.DeleteOptions{}); err != nil {
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
		ID:      ID,
		Options: option.NewIntOptions(&EndpointMutableOptionLibrary),
		Status:  NewEndpointStatus(),
		state:   state,
	}
}

// NewEndpointFromChangeModel creates a new endpoint from a request
func NewEndpointFromChangeModel(base *models.EndpointChangeRequest) (*Endpoint, error) {
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
			OrchestrationIdentity: pkgLabels.Labels{},
			OrchestrationInfo:     pkgLabels.Labels{},
		},
		state:  "",
		Status: NewEndpointStatus(),
	}

	ep.SetStateLocked(string(base.State), "Endpoint creation")
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

	lblSpec := &models.LabelConfigurationSpec{
		User: e.OpLabels.Custom.GetModel(),
	}
	lblMdl := &models.LabelConfigurationStatus{
		Realized:         lblSpec,
		SecurityRelevant: e.OpLabels.OrchestrationIdentity.GetModel(),
		Derived:          e.OpLabels.OrchestrationInfo.GetModel(),
		Disabled:         e.OpLabels.Disabled.GetModel(),
	}
	// Sort these slices since they come out in random orders. This allows
	// reflect.DeepEqual to succeed.
	sort.StringSlice(lblSpec.User).Sort()
	sort.StringSlice(lblMdl.Disabled).Sort()
	sort.StringSlice(lblMdl.SecurityRelevant).Sort()
	sort.StringSlice(lblMdl.Derived).Sort()

	controllerMdl := e.controllers.GetStatusModel()
	sort.Slice(controllerMdl, func(i, j int) bool { return controllerMdl[i].Name < controllerMdl[j].Name })

	spec := &models.EndpointConfigurationSpec{
		LabelConfiguration: lblSpec,
		Options:            *e.Options.GetMutableModel(),
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
				ContainerID:      e.DockerID,
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

	for policyMapKey := range e.realizedMapState {
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the PolicyKey no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		switch policymap.TrafficDirection(policyMapKey.TrafficDirection) {
		case policymap.Ingress:
			realizedIngressIdentities = append(realizedIngressIdentities, int64(policyMapKey.Identity))
		case policymap.Egress:
			realizedEgressIdentities = append(realizedEgressIdentities, int64(policyMapKey.Identity))
		default:
			log.WithField(logfields.TrafficDirection, policymap.TrafficDirection(policyMapKey.TrafficDirection)).Error("Unexpected traffic direction present in realized PolicyMap state for endpoint")
		}
	}

	desiredIngressIdentities := make([]int64, 0)
	desiredEgressIdentities := make([]int64, 0)

	for policyMapKey := range e.desiredMapState {
		if policyMapKey.DestPort != 0 {
			// If the port is non-zero, then the PolicyKey no longer only applies
			// at L3. AllowedIngressIdentities and AllowedEgressIdentities
			// contain sets of which identities (i.e., label-based L3 only)
			// are allowed, so anything which contains L4-related policy should
			// not be added to these sets.
			continue
		}
		switch policymap.TrafficDirection(policyMapKey.TrafficDirection) {
		case policymap.Ingress:
			desiredIngressIdentities = append(desiredIngressIdentities, int64(policyMapKey.Identity))
		case policymap.Egress:
			desiredEgressIdentities = append(desiredEgressIdentities, int64(policyMapKey.Identity))
		default:
			log.WithField(logfields.TrafficDirection, policymap.TrafficDirection(policyMapKey.TrafficDirection)).Error("Unexpected traffic direction present in desired PolicyMap state for endpoint")
		}
	}

	policyIngressEnabled := e.Options.IsEnabled(option.IngressPolicy)
	policyEgressEnabled := e.Options.IsEnabled(option.EgressPolicy)

	policyEnabled := models.EndpointPolicyEnabledNone
	switch {
	case policyIngressEnabled && policyEgressEnabled:
		policyEnabled = models.EndpointPolicyEnabledBoth
	case policyIngressEnabled:
		policyEnabled = models.EndpointPolicyEnabledIngress
	case policyEgressEnabled:
		policyEnabled = models.EndpointPolicyEnabledEgress
	}

	// Make a shallow copy of the stats.
	e.proxyStatisticsMutex.RLock()
	proxyStats := make([]*models.ProxyStatistics, 0, len(e.proxyStatistics))
	for _, stats := range e.proxyStatistics {
		statsCopy := *stats
		proxyStats = append(proxyStats, &statsCopy)
	}
	e.proxyStatisticsMutex.RUnlock()
	sortProxyStats(proxyStats)

	mdl := &models.EndpointPolicy{
		ID:                       int64(e.SecurityIdentity.ID),
		Build:                    int64(e.Iteration),
		PolicyRevision:           int64(e.policyRevision),
		AllowedIngressIdentities: realizedIngressIdentities,
		AllowedEgressIdentities:  realizedEgressIdentities,
		CidrPolicy:               e.L3Policy.GetModel(),
		L4:                       e.RealizedL4Policy.GetModel(),
		PolicyEnabled:            policyEnabled,
	}

	desiredMdl := &models.EndpointPolicy{
		ID:                       int64(e.SecurityIdentity.ID),
		Build:                    int64(e.Iteration),
		PolicyRevision:           int64(e.nextPolicyRevision),
		AllowedIngressIdentities: desiredIngressIdentities,
		AllowedEgressIdentities:  desiredEgressIdentities,
		CidrPolicy:               e.L3Policy.GetModel(),
		L4:                       e.DesiredL4Policy.GetModel(),
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

// GetID returns the endpoint's ID
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

// GetIPv4Address returns the IPv4 address of the endpoint
func (e *Endpoint) GetIPv4Address() string {
	return e.IPv4.String()
}

// GetIPv6Address returns the IPv6 address of the endpoint
func (e *Endpoint) GetIPv6Address() string {
	return e.IPv6.String()
}

func (e *Endpoint) HasSidecarProxy() bool {
	return e.hasSidecarProxy
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

// DirectoryPath returns the directory name for this endpoint bpf program.
func (e *Endpoint) DirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d", e.ID))
}

// FailedDirectoryPath returns the directory name for this endpoint bpf program
// failed builds.
func (e *Endpoint) FailedDirectoryPath() string {
	return filepath.Join(".", fmt.Sprintf("%d%s", e.ID, "_next_fail"))
}

func (e *Endpoint) Allows(id identityPkg.NumericIdentity) bool {
	e.UnconditionalRLock()
	defer e.RUnlock()

	keyToLookup := policymap.PolicyKey{
		Identity:         uint32(id),
		TrafficDirection: policymap.Ingress.Uint8(),
	}

	_, ok := e.desiredMapState[keyToLookup]
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
func optionChanged(key string, value int, data interface{}) {
}

// applyOptsLocked applies the given options to the endpoint's options and
// returns true if there were any options changed.
func (e *Endpoint) applyOptsLocked(opts map[string]string) bool {
	return e.Options.ApplyValidated(opts, optionChanged, e) > 0
}

// ForcePolicyCompute marks the endpoint for forced bpf regeneration.
func (e *Endpoint) ForcePolicyCompute() {
	e.forcePolicyCompute = true
}

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
}

// ConntrackLocal determines whether this endpoint is currently using a local
// table to handle connection tracking (true), or the global table (false).
func (e *Endpoint) ConntrackLocal() bool {
	e.UnconditionalRLock()
	defer e.RUnlock()

	if e.SecurityIdentity == nil || !e.Options.IsEnabled(option.ConntrackLocal) {
		return false
	}

	return true
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
			if err == nil || strings.HasSuffix(file.Name(), "_next_fail") {
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

	ep.SetStateLocked(StateRestoring, "Endpoint restoring")

	return &ep, nil
}

func (e *Endpoint) RemoveFromGlobalPolicyMap() error {
	gpm, err := policymap.OpenGlobalMap(e.PolicyGlobalMapPathLocked())
	if err == nil {
		// We need to remove ourselves from global map, so that
		// resources (prog/map reference counts) can be released.
		gpm.Delete(uint32(e.ID), policymap.AllPorts, u8proto.All, policymap.Ingress)
		gpm.Delete(uint32(e.ID), policymap.AllPorts, u8proto.All, policymap.Egress)
		gpm.Close()
	}

	return err
}

// GetBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func (e *Endpoint) GetBPFKeys() []*lxcmap.EndpointKey {
	key := lxcmap.NewEndpointKey(e.IPv6.IP())

	if e.IPv4 != nil {
		key4 := lxcmap.NewEndpointKey(e.IPv4.IP())
		return []*lxcmap.EndpointKey{key, key4}
	}

	return []*lxcmap.EndpointKey{key}
}

// GetBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
func (e *Endpoint) GetBPFValue() (*lxcmap.EndpointInfo, error) {
	mac, err := e.LXCMAC.Uint64()
	if err != nil {
		return nil, fmt.Errorf("invalid LXC MAC: %v", err)
	}

	nodeMAC, err := e.NodeMAC.Uint64()
	if err != nil {
		return nil, fmt.Errorf("invalid node MAC: %v", err)
	}

	info := &lxcmap.EndpointInfo{
		IfIndex: uint32(e.IfIndex),
		// Store security identity in network byte order so it can be
		// written into the packet without an additional byte order
		// conversion.
		LxcID:   e.ID,
		MAC:     lxcmap.MAC(mac),
		NodeMAC: lxcmap.MAC(nodeMAC),
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
// or if endpoint regeneration was unable to be triggered.
func (e *Endpoint) Update(owner Owner, cfg *models.EndpointConfigurationSpec) error {
	if err := e.LockAlive(); err != nil {
		return err
	}
	e.getLogger().WithField("configuration-options", cfg).Debug("updating endpoint configuration options")

	if err := e.Options.Validate(cfg.Options); err != nil {
		e.Unlock()
		return UpdateValidationError{err.Error()}
	}

	// Option changes may be overridden by the policy configuration.
	// Currently we return all-OK even in that case.
	needToRegenerate, err := e.TriggerPolicyUpdatesLocked(owner, cfg.Options)
	if err != nil {
		e.Unlock()
		return UpdateCompilationError{err.Error()}
	}

	reason := "endpoint was updated via API"

	// If configuration options are provided, we only regenerate if necessary.
	// Otherwise always regenerate.
	if cfg.Options == nil {
		needToRegenerate = true
		reason = "endpoint was manually regenerated via API"
	}

	if needToRegenerate {
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
				stateTransitionSucceeded := e.SetStateLocked(StateWaitingToRegenerate, reason)
				if stateTransitionSucceeded {
					e.Unlock()
					e.Regenerate(owner, reason)
					return nil
				}
				e.Unlock()
			case <-timeout:
				if err = e.LockAlive(); err != nil {
					return err
				}
				e.getLogger().Warningf("timed out waiting for endpoint state to change")
				e.Unlock()
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

// replaceInformationLabels replaces the information labels of the endpoint.
// Passing a nil set of labels will not perform any action.
// Must be called with e.Mutex.Lock().
func (e *Endpoint) replaceInformationLabels(l pkgLabels.Labels) {
	if l == nil {
		return
	}
	e.OpLabels.OrchestrationInfo.MarkAllForDeletion()

	scopedLog := e.getLogger()

	for _, v := range l {
		if e.OpLabels.OrchestrationInfo.UpsertLabel(v) {
			scopedLog.WithField(logfields.Labels, logfields.Repr(v)).Debug("Assigning information label")
		}
	}
	e.OpLabels.OrchestrationInfo.DeleteMarked()
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

	changed := false

	e.OpLabels.OrchestrationIdentity.MarkAllForDeletion()
	e.OpLabels.Disabled.MarkAllForDeletion()

	scopedLog := e.getLogger()

	for k, v := range l {
		// A disabled identity label stays disabled without value updates
		if e.OpLabels.Disabled[k] != nil {
			e.OpLabels.Disabled[k].ClearDeletionMark()
		} else if e.OpLabels.OrchestrationIdentity.UpsertLabel(v) {
			scopedLog.WithField(logfields.Labels, logfields.Repr(v)).Debug("Assigning security relevant label")
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

	return rev
}

// LeaveLocked removes the endpoint's directory from the system. Must be called
// with Endpoint's mutex AND BuildMutex locked.
func (e *Endpoint) LeaveLocked(owner Owner, proxyWaitGroup *completion.WaitGroup) []error {
	errors := []error{}

	owner.RemoveFromEndpointQueue(uint64(e.ID))
	if e.SecurityIdentity != nil && e.RealizedL4Policy != nil {
		// Passing a new map of nil will purge all redirects
		e.removeOldRedirects(owner, nil, proxyWaitGroup)
	}

	if e.PolicyMap != nil {
		if err := e.PolicyMap.Close(); err != nil {
			errors = append(errors, fmt.Errorf("unable to close policymap %s: %s", e.PolicyGlobalMapPathLocked(), err))
		}
	}

	if e.SecurityIdentity != nil {
		err := e.SecurityIdentity.Release()
		if err != nil {
			errors = append(errors, fmt.Errorf("unable to release identity: %s", err))
		}
		// TODO: Check if network policy was created even without SecurityIdentity
		owner.RemoveNetworkPolicy(e)
		e.SecurityIdentity = nil
	}

	e.removeDirectory()
	e.removeFailedDirectory()
	e.controllers.RemoveAll()
	e.cleanPolicySignals()

	e.scrubIPsInConntrackTableLocked()

	e.SetStateLocked(StateDisconnected, "Endpoint removed")

	e.getLogger().Info("Removed endpoint")

	return errors
}

func (e *Endpoint) removeDirectory() {
	os.RemoveAll(e.DirectoryPath())
}

func (e *Endpoint) removeFailedDirectory() {
	os.RemoveAll(e.FailedDirectoryPath())
}

func (e *Endpoint) RemoveDirectory() {
	e.UnconditionalLock()
	defer e.Unlock()
	e.removeDirectory()
}

// CreateDirectory creates endpoint directory
func (e *Endpoint) CreateDirectory() error {
	if err := e.LockAlive(); err != nil {
		return err
	}
	defer e.Unlock()
	lxcDir := e.DirectoryPath()
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
	e.UnconditionalLock()
	e.ContainerName = name
	e.Unlock()
}

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.k8sNamespace
}

// SetK8sNamespace modifies the endpoint's pod name
func (e *Endpoint) SetK8sNamespace(name string) {
	e.UnconditionalLock()
	e.k8sNamespace = name
	e.Unlock()
}

// GetK8sPodName returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sPodName() string {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.k8sPodName
}

// GetK8sNamespaceAndPodNameLocked returns the namespace and pod name.  This
// function requires e.Mutex to be held.
func (e *Endpoint) GetK8sNamespaceAndPodNameLocked() string {
	return e.k8sNamespace + "/" + e.k8sPodName
}

// SetK8sPodName modifies the endpoint's pod name
func (e *Endpoint) SetK8sPodName(name string) {
	e.UnconditionalLock()
	e.k8sPodName = name
	e.Unlock()
}

// SetContainerID modifies the endpoint's container ID
func (e *Endpoint) SetContainerID(id string) {
	e.UnconditionalLock()
	e.DockerID = id
	e.Unlock()
}

// GetContainerID returns the endpoint's container ID
func (e *Endpoint) GetContainerID() string {
	e.UnconditionalRLock()
	defer e.RUnlock()

	return e.DockerID
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
	if len(e.DockerID) <= caplen {
		return e.DockerID
	}

	return e.DockerID[:caplen]

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
			"file": fileName,
			"line": fileLine,
		}).Info("Invalid state transition skipped")
	}
	e.logStatusLocked(Other, Warning, fmt.Sprintf("Skipped invalid state transition to %s due to: %s", toState, reason))
	return false

OKState:
	e.state = toState
	e.logStatusLocked(Other, OK, reason)

	// Initial state transitions i.e nil --> waiting-for-identity
	// need to be handled correctly while updating metrics.
	// Note that if we are transitioning from some state to restoring
	// state, we cannot decrement the old state counters as they will not
	// be accounted for in the metrics.
	if fromState != "" && toState != StateRestoring {
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

	if fromState != "" && toState != StateRestoring {
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

// bumpPolicyRevisionLocked marks the endpoint to be running the next scheduled
// policy revision as setup by e.regenerate()
// endpoint.Mutex should held.
func (e *Endpoint) bumpPolicyRevisionLocked(revision uint64) {
	if revision > e.policyRevision {
		e.setPolicyRevision(revision)
	}
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
	if lbls := e.OpLabels.OrchestrationIdentity.FindReserved(); lbls != nil {
		return fmt.Errorf("Endpoint cannot be modified by API call")
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
		return nil
	}

	newLabels := e.OpLabels.DeepCopy()

	for k := range delLabels {
		// The change request is accepted if the label is on
		// any of the lists. If the label is already disabled,
		// we will simply ignore that change.
		if newLabels.Custom[k] == nil && newLabels.OrchestrationIdentity[k] == nil && newLabels.Disabled[k] == nil {
			e.Unlock()
			return fmt.Errorf("label %s not found", k)
		}

		if v := newLabels.OrchestrationIdentity[k]; v != nil {
			delete(newLabels.OrchestrationIdentity, k)
			newLabels.Disabled[k] = v
		}

		if newLabels.Custom[k] != nil {
			delete(newLabels.Custom, k)
		}
	}

	for k, v := range addLabels {
		if newLabels.Disabled[k] != nil { // Restore label.
			delete(newLabels.Disabled, k)
			newLabels.OrchestrationIdentity[k] = v
		} else if newLabels.OrchestrationIdentity[k] != nil { // Replace label's source and value.
			newLabels.OrchestrationIdentity[k] = v
		} else {
			newLabels.Custom[k] = v
		}
	}

	e.OpLabels = *newLabels

	// Mark with StateWaitingForIdentity, it will be set to
	// StateWaitingToRegenerate after the identity resolution has been
	// completed
	e.SetStateLocked(StateWaitingForIdentity, "Triggering identity resolution due to updated identity labels")

	e.identityRevision++
	rev := e.identityRevision

	e.Unlock()

	e.runLabelsResolver(owner, rev)

	return nil
}

// IsInit returns true if the endpoint still hasn't received identity labels,
// i.e. has the special identity with label reserved:init.
func (e *Endpoint) IsInit() bool {
	init := e.OpLabels.GetIdentityLabel(pkgLabels.IDNameInit)
	return init != nil && init.Source == pkgLabels.LabelSourceReserved
}

// UpdateLabels is called to update the labels of an endpoint. Calls to this
// function do not necessarily mean that the labels actually changed. The
// container runtime layer will periodically synchronize labels.
//
// If a net label changed was performed, the endpoint will receive a new
// identity and will be regenerated. Both of these operations will happen in
// the background.
func (e *Endpoint) UpdateLabels(owner Owner, identityLabels, infoLabels pkgLabels.Labels) {
	log.WithFields(logrus.Fields{
		logfields.ContainerID:    e.GetShortContainerID(),
		logfields.EndpointID:     e.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		logfields.InfoLabels:     infoLabels.String(),
	}).Debug("Refreshing labels of endpoint")

	if err := e.LockAlive(); err != nil {
		e.LogDisconnectedMutexAction(err, "when trying to refresh endpint labels")
		return
	}

	e.replaceInformationLabels(infoLabels)
	// replace identity labels and update the identity if labels have changed
	rev := e.replaceIdentityLabels(identityLabels)
	e.Unlock()
	if rev != 0 {
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

// Must be called with e.Mutex NOT held.
func (e *Endpoint) runLabelsResolver(owner Owner, myChangeRev int) {
	// NOTE: UnconditionalLock is used here only for logging
	e.UnconditionalLock()

	newLabels := e.OpLabels.IdentityLabels()
	scopedLog := e.getLogger().WithField(logfields.IdentityLabels, newLabels)
	e.Unlock()

	// If we are certain we can resolve the identity without accessing the KV
	// store, do it first synchronously right now. This can reduce the number
	// of regenerations for the endpoint during its initialization.
	if identityPkg.IdentityAllocationIsLocal(newLabels) {
		scopedLog.Debug("Endpoint has reserved identity, changing synchronously")
		err := e.identityLabelsChanged(owner, myChangeRev)
		if err != nil {
			scopedLog.WithError(err).Warn("Error changing endpoint identity")
		}
	}

	ctrlName := fmt.Sprintf("resolve-identity-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func() error {
				return e.identityLabelsChanged(owner, myChangeRev)
			},
			RunInterval: 5 * time.Minute,
		},
	)
}

func (e *Endpoint) identityLabelsChanged(owner Owner, myChangeRev int) error {
	if err := e.RLockAlive(); err != nil {
		return err
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

	identity, _, err := identityPkg.AllocateIdentity(newLabels)
	if err != nil {
		err = fmt.Errorf("unable to resolve identity: %s", err)
		e.LogStatus(Other, Warning, fmt.Sprintf("%s (will retry)", err.Error()))
		return err
	}

	if err := e.LockAlive(); err != nil {
		return err
	}

	// Since we unlocked the endpoint and re-locked, the label update may already be obsolete
	if e.identityResolutionIsObsolete(myChangeRev) {
		e.Unlock()

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

	e.SetIdentity(identity)

	readyToRegenerate := e.SetStateLocked(StateWaitingToRegenerate, "Triggering regeneration due to new identity")

	// Unconditionally force policy recomputation after a new identity has been
	// assigned.
	e.ForcePolicyCompute()

	e.Unlock()

	if readyToRegenerate {
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
	// NOTE: UnconditionalLock is used here because this method handles endpoint in disconnected state on its own
	e.UnconditionalLock()
	defer e.Unlock()
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

// IPs returns the slice of valid IPs for this endpoint.
func (e *Endpoint) IPs() []net.IP {
	ips := []net.IP{}
	if e.IPv4 != nil {
		ips = append(ips, e.IPv4.IP())
	}
	if e.IPv6 != nil {
		ips = append(ips, e.IPv6.IP())
	}
	return ips
}

// InsertEvent is called when the endpoint is inserted into the endpoint
// manager. The endpoint must be read locked.
func (e *Endpoint) InsertEvent() {
	e.getLogger().Info("New endpoint")
}

// syncPolicyMap attempts to synchronize the PolicyMap for this endpoint to
// contain the set of PolicyKeys represented by the endpoint's desiredMapState.
// It checks the current contents of the endpoint's PolicyMap and deletes any
// PolicyKeys that are not present in the endpoint's desiredMapState. It then
// adds any keys that are not present in the map. When a key from desiredMapState
// is inserted successfully to the endpoint's BPF PolicyMap, it is added to the
// endpoint's realizedMapState field. Returns an error if the endpoint's BPF
// PolicyMap is unable to be dumped, or any update operation to the map fails.
// Must be called with e.Mutex locked.
func (e *Endpoint) syncPolicyMap() error {

	if e.realizedMapState == nil {
		e.realizedMapState = make(PolicyMapState)
	}

	if e.desiredMapState == nil {
		e.desiredMapState = make(PolicyMapState)
	}

	if e.PolicyMap == nil {
		return fmt.Errorf("not syncing PolicyMap state for endpoint because PolicyMap is nil")
	}

	currentMapContents, err := e.PolicyMap.DumpToSlice()

	// If map is unable to be dumped, attempt to close map and open it again.
	// See GH-4229.
	if err != nil {
		e.getLogger().WithError(err).Error("unable to dump PolicyMap when trying to sync desired and realized PolicyMap state")

		// Close to avoid leaking of file descriptors, but still continue in case
		// Close() does not succeed, because otherwise the map will never be
		// opened again unless the agent is restarted.
		err := e.PolicyMap.Close()
		if err != nil {
			e.getLogger().WithError(err).Error("unable to close PolicyMap which was not able to be dumped")
		}

		e.PolicyMap, _, err = policymap.OpenMap(e.PolicyMapPathLocked())
		if err != nil {
			return fmt.Errorf("unable to open PolicyMap for endpoint: %s", err)
		}

		// Try to dump again, fail if error occurs.
		currentMapContents, err = e.PolicyMap.DumpToSlice()
		if err != nil {
			return err
		}
	}

	errors := []error{}

	for _, entry := range currentMapContents {
		// Convert key to host-byte order for lookup in the desiredMapState.
		keyHostOrder := entry.Key.ToHost()

		// If key that is in policy map is not in desired state, just remove it.
		if _, ok := e.desiredMapState[keyHostOrder]; !ok {
			// Can pass key with host byte-order fields, as it will get
			// converted to network byte-order.
			err := e.PolicyMap.DeleteKey(keyHostOrder)
			if err != nil {
				e.getLogger().WithError(err).Errorf("Failed to delete PolicyMap key %s", entry.Key)
				errors = append(errors, err)
			} else {
				// Operation was successful, remove from realized state.
				delete(e.realizedMapState, keyHostOrder)
			}
		}
	}

	for keyToAdd, entry := range e.desiredMapState {
		if oldEntry, ok := e.realizedMapState[keyToAdd]; !ok || oldEntry != entry {
			err := e.PolicyMap.AllowKey(keyToAdd, entry.ProxyPort)
			if err != nil {
				e.getLogger().WithError(err).Errorf("Failed to add PolicyMap key %s %d", keyToAdd, entry.ProxyPort)
				errors = append(errors, err)
			} else {
				// Operation was successful, add to realized state.
				e.realizedMapState[keyToAdd] = entry
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("synchronizing desired PolicyMap state failed: %s", errors)
	}

	return nil
}

func (e *Endpoint) syncPolicyMapController() {
	ctrlName := fmt.Sprintf("sync-policymap-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func() (reterr error) {
				if err := e.LockAlive(); err != nil {
					e.LogDisconnectedMutexAction(err, "before syncing policy maps in controller")
					return nil
				}
				defer e.Unlock()
				return e.syncPolicyMap()
			},
			RunInterval: 1 * time.Minute,
		},
	)
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

// LockAlive returns error if endpoint was removed, locks underlying mutex otherwise
func (e *Endpoint) LockAlive() error {
	e.mutex.Lock()
	if e.IsDisconnecting() {
		e.mutex.Unlock()
		return fmt.Errorf("lock failed: endpoint is in the process of being removed")
	}
	return nil
}

// Unlock unlocks endpoint mutex
func (e *Endpoint) Unlock() {
	e.mutex.Unlock()
}

// RLockAlive returns error if endpoint was removed, read locks underlying mutex otherwise
func (e *Endpoint) RLockAlive() error {
	e.mutex.RLock()
	if e.IsDisconnecting() {
		e.mutex.RUnlock()
		return fmt.Errorf("rlock failed: endpoint is in the process of being removed")
	}
	return nil
}

// RUnlock read unlocks endpoint mutex
func (e *Endpoint) RUnlock() {
	e.mutex.RUnlock()
}

// UnconditionalLock should be used only for locking endpoint for
// - setting its state to StateDisconnected
// - handling regular Lock errors
// - reporting endpoint status (like in LogStatus method)
// Use Lock in all other cases
func (e *Endpoint) UnconditionalLock() {
	e.mutex.Lock()
}

// UnconditionalRLock should be used only for reporting endpoint state
func (e *Endpoint) UnconditionalRLock() {
	e.mutex.RLock()
}

// LogDisconnectedMutexAction gets the logger and logs given error with context
func (e *Endpoint) LogDisconnectedMutexAction(err error, context string) {
	e.mutex.Lock()
	logger := e.getLogger()
	logger.WithError(err).Error(context)
	e.mutex.Unlock()
}

// doGarbageCollectConntrack is usd by garbageCollectConntrack and should not be
// called directly.
func (e *Endpoint) doGarbageCollectConntrack(isIPv6 bool, filter *ctmap.GCFilter) {
	var file, mapType string

	if e.Options != nil && e.Options.IsEnabled(option.ConntrackLocal) {
		mapType, file = ctmap.GetMapTypeAndPath(e, isIPv6)
	} else {
		mapType, file = ctmap.GetMapTypeAndPath(nil, isIPv6)
	}

	m, err := bpf.OpenMap(file)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, file).Warn("Unable to open map")
		return
	}
	defer m.Close()

	ctmap.GC(m, mapType, filter)
}

// garbageCollectConntrack will run the ctmap.GC() on either the endpoint's
// local conntrack table or the global conntrack table.
//
// The endponit lock must be held
func (e *Endpoint) garbageCollectConntrack(filter *ctmap.GCFilter) {
	if !option.Config.IPv4Disabled {
		e.doGarbageCollectConntrack(false, filter)
	}

	e.doGarbageCollectConntrack(true, filter)
}

func (e *Endpoint) scrubIPsInConntrackTableLocked() {
	e.garbageCollectConntrack(&ctmap.GCFilter{
		MatchIPs: map[string]struct{}{
			e.IPv4.String(): {},
			e.IPv6.String(): {},
		},
	})
}

func (e *Endpoint) scrubIPsInConntrackTable() {
	e.UnconditionalLock()
	e.scrubIPsInConntrackTableLocked()
	e.Unlock()
}
