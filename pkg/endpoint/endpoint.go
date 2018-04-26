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
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
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

func init() {
	for k, v := range EndpointMutableOptionLibrary {
		EndpointOptionLibrary[k] = v
	}
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

	// Mutex protects write operations to this endpoint structure
	Mutex lock.RWMutex `json:"-"`

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

// NewEndpointWithState creates a new endpoint useful for testing purposes
func NewEndpointWithState(ID uint16, state string) *Endpoint {
	return &Endpoint{
		ID:     ID,
		Opts:   option.NewBoolOptions(&EndpointOptionLibrary),
		Status: NewEndpointStatus(),
		state:  state,
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

// StringID returns the endpoint's ID in a string.
func (e *Endpoint) StringID() string {
	return strconv.Itoa(int(e.ID))
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

// Update modifies the endpoint options and *always* tries to regenerate the
// endpoint's program. Returns an error if the provided options are not valid,
// if there was an issue triggering policy updates for the given endpoint,
// or if endpoint regeneration was unable to be triggered.
func (e *Endpoint) Update(owner Owner, cfg *models.EndpointConfigurationSpec) error {
	e.getLogger().WithField("configuration-options", cfg).Debug("updating endpoint configuration options")

	e.Mutex.Lock()
	if err := e.Opts.Validate(cfg.Options); err != nil {
		e.Mutex.Unlock()
		return UpdateValidationError{err.Error()}
	}

	// Option changes may be overridden by the policy configuration.
	// Currently we return all-OK even in that case.
	needToRegenerate, ctCleaned, err := e.TriggerPolicyUpdatesLocked(owner, cfg.Options)
	if err != nil {
		e.Mutex.Unlock()
		ctCleaned.Wait()
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

		// Default timeout for PATCH /endpoint/{id}/config is 30 seconds, so put
		// timeout in this function a bit below that timeout. If the timeout
		// for clients in API is below this value, they will get a message containing
		// "context deadline exceeded".
		stateChangeTimeout := time.Duration(25 * time.Second)

		// Check up until stateChangeTimeout seconds for endpoint state before
		// trying to update configuration.
		timeout := time.After(stateChangeTimeout)

		// Check for endpoint state every second.
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		e.Mutex.Unlock()
		for {
			select {
			case <-ticker.C:
				e.Mutex.Lock()
				// Check endpoint state before attempting configuration update because
				// configuration updates can only be applied when the endpoint is in
				// specific states. See GH-3058.
				stateTransitionSucceeded := e.SetStateLocked(StateWaitingToRegenerate, reason)
				if stateTransitionSucceeded {
					e.Mutex.Unlock()
					ctCleaned.Wait()
					e.Regenerate(owner, reason)
					return nil
				}
				e.Mutex.Unlock()
			case <-timeout:
				e.Mutex.Lock()
				e.getLogger().Warningf("timed out waiting for endpoint state to change")
				e.Mutex.Unlock()
				ctCleaned.Wait()
				return UpdateStateChangeError{fmt.Sprintf("unable to regenerate endpoint program because state transition to %s was unsuccessful; check `cilium endpoint log %d` for more information", StateWaitingToRegenerate, e.ID)}
			}
		}

	}

	e.Mutex.Unlock()
	ctCleaned.Wait()

	return nil
}

// LeaveLocked removes the endpoint's directory from the system. Must be called
// with Endpoint's mutex AND BuildMutex locked.
func (e *Endpoint) LeaveLocked(owner Owner) []error {
	errors := []error{}

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

	e.L3Maps.Close()
	e.removeDirectory()
	e.controllers.RemoveAll()
	e.cleanPolicySignals()

	e.SetStateLocked(StateDisconnected, "Endpoint removed")

	return errors
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
