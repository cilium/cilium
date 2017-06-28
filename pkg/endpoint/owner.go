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
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {
	// Must return true if tracing of the policy resolution is to be enabled
	TracingEnabled() bool

	// Must return true if dry mode is enabled
	DryModeEnabled() bool

	// PolicyEnabled returns whether policy enforcement is enabled
	PolicyEnabled() bool

	// EnablePolicyEnforcement returns whether owner should enable policy enforcement.
	EnablePolicyEnforcement() bool

	// UpdateEndpointPolicyEnforcement returns whether policy enforcement
	// should be enabled for the specified endpoint.
	UpdateEndpointPolicyEnforcement(e *Endpoint) bool

	// GetPolicyEnforcementType returns the type of policy enforcement for the Owner.
	PolicyEnforcement() string

	// AlwaysAllowLocalhost returns true if localhost is always allowed to
	// reach local endpoints
	AlwaysAllowLocalhost() bool

	// Must return an instance of a ConsumableCache
	GetConsumableCache() *policy.ConsumableCache

	// Must resolve label id to an identity
	GetCachedLabelList(ID policy.NumericIdentity) (labels.LabelArray, error)

	// Must return the policy repository
	GetPolicyRepository() *policy.Repository

	// Return the next available global identity
	GetCachedMaxLabelID() (policy.NumericIdentity, error)

	// UpdateProxyRedirect must update the redirect configuration of an endpoint in the prox
	UpdateProxyRedirect(e *Endpoint, l4 *policy.L4Filter) (uint16, error)

	// RemoveProxyRedirect must remove the redirect installed by UpdateProxyRedirect
	RemoveProxyRedirect(e *Endpoint, l4 *policy.L4Filter) error

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

	// Annotates endpoint e with an annotation with key annotationKey, and value annotationValue.
	AnnotateEndpoint(e *Endpoint, annotationKey, annotationValue string)
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
