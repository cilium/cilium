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
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/policy"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {

	// Must return true if dry mode is enabled
	DryModeEnabled() bool

	// EnableEndpointPolicyEnforcement returns whether policy enforcement
	// should be enabled for the specified endpoint.
	EnableEndpointPolicyEnforcement(e *Endpoint) (bool, bool)

	// GetPolicyEnforcementType returns the type of policy enforcement for the Owner.
	PolicyEnforcement() string

	// Must return the policy repository
	GetPolicyRepository() *policy.Repository

	// UpdateProxyRedirect must update the redirect configuration of an endpoint in the proxy
	UpdateProxyRedirect(e *Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error)

	// RemoveProxyRedirect must remove the redirect installed by UpdateProxyRedirect
	RemoveProxyRedirect(e *Endpoint, id string, proxyWaitGroup *completion.WaitGroup) error

	// UpdateNetworkPolicy adds or updates a network policy in the set
	// published to L7 proxies.
	UpdateNetworkPolicy(e *Endpoint, policy *policy.L4Policy,
		labelsMap identity.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool, proxyWaitGroup *completion.WaitGroup) error

	// RemoveNetworkPolicy removes a network policy from the set published to
	// L7 proxies.
	RemoveNetworkPolicy(e *Endpoint)

	// GetStateDir must return path to the state directory
	GetStateDir() string

	// Must return path to BPF template files directory
	GetBpfDir() string

	// QueueEndpointBuild puts the given request in the processing queue
	QueueEndpointBuild(*Request)

	// RemoveFromEndpointQueue removes all requests from the working queue
	RemoveFromEndpointQueue(epID uint64)

	// Returns true if debugging has been enabled
	DebugEnabled() bool

	// GetCompilationLock returns the mutex responsible for synchronizing compilation
	// of BPF programs.
	GetCompilationLock() *lock.RWMutex

	// SendNotification is called to emit an agent notification
	SendNotification(typ monitor.AgentNotification, text string) error
}

// Request is used to create the endpoint's request and send it to the endpoints
// processor.
type Request struct {
	// ID request ID.
	ID uint64
	// MyTurn is used to know when is its turn.
	MyTurn chan bool
	// Done is used to tell the Processor the request as finished.
	Done chan bool
	// ExternalDone is used for external listeners this request as finished
	// if returns true the build was successful, false otherwise.
	ExternalDone chan bool
}
