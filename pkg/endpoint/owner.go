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

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {

	// Must return the policy repository
	GetPolicyRepository() *policy.Repository

	// UpdateProxyRedirect must update the redirect configuration of an endpoint in the proxy
	UpdateProxyRedirect(e *Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc)

	// RemoveProxyRedirect must remove the redirect installed by UpdateProxyRedirect
	RemoveProxyRedirect(e *Endpoint, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc)

	// UpdateNetworkPolicy adds or updates a network policy in the set
	// published to L7 proxies.
	UpdateNetworkPolicy(e *Endpoint, policy *policy.L4Policy,
		labelsMap cache.IdentityCache, proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc)

	// RemoveNetworkPolicy removes a network policy from the set published to
	// L7 proxies.
	RemoveNetworkPolicy(e *Endpoint)

	// QueueEndpointBuild puts the given endpoint in the processing queue
	QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error)

	// RemoveFromEndpointQueue removes an endpoint from the working queue
	RemoveFromEndpointQueue(epID uint64)

	// GetCompilationLock returns the mutex responsible for synchronizing compilation
	// of BPF programs.
	GetCompilationLock() *lock.RWMutex

	// SendNotification is called to emit an agent notification
	SendNotification(typ monitorAPI.AgentNotification, text string) error

	// Datapath returns a reference to the datapath implementation.
	Datapath() datapath.Datapath
}
