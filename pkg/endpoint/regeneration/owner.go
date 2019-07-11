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

package regeneration

import (
	"context"
	"strings"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {

	// Must return the policy repository
	GetPolicyRepository() PolicyRepository

	// UpdateProxyRedirect must update the redirect configuration of an endpoint in the proxy
	UpdateProxyRedirect(e EndpointUpdater, l4 PolicyL4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc)

	// RemoveProxyRedirect must remove the redirect installed by UpdateProxyRedirect
	RemoveProxyRedirect(e EndpointInfoSource, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc)

	// UpdateNetworkPolicy adds or updates a network policy in the set
	// published to L7 proxies.
	UpdateNetworkPolicy(e EndpointUpdater, policy L4Policy,
		proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc)

	// RemoveNetworkPolicy removes a network policy from the set published to
	// L7 proxies.
	RemoveNetworkPolicy(e EndpointInfoSource)

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

	// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
	GetNodeSuffix() string

	// UpdateIdentities propagates identity updates to selectors
	UpdateIdentities(added, deleted cache.IdentityCache)
}

// EndpointInfoSource returns information about an endpoint being proxied.
// The read lock must be held when calling any method.
type EndpointInfoSource interface {
	UnconditionalRLock()
	RUnlock()
	GetID() uint64
	GetIPv4Address() string
	GetIPv6Address() string
	GetIdentity() identity.NumericIdentity
	GetLabels() []string
	GetLabelsSHA() string
	HasSidecarProxy() bool
	ConntrackName() string
	GetIngressPolicyEnabledLocked() bool
	GetEgressPolicyEnabledLocked() bool
	ProxyID(l4 PolicyL4Filter) string
}

// EndpointUpdater returns information about an endpoint being proxied and
// is called back to update the endpoint when proxy events occur.
// This is a subset of `Endpoint`.
type EndpointUpdater interface {
	EndpointInfoSource
	// OnProxyPolicyUpdate is called when the proxy acknowledges that it
	// has applied a policy.
	OnProxyPolicyUpdate(policyRevision uint64)

	// UpdateProxyStatistics updates the Endpoint's proxy statistics to account
	// for a new observed flow with the given characteristics.
	UpdateProxyStatistics(l7Protocol string, port uint16, ingress, request bool, verdict accesslog.FlowVerdict)
}

// PolicyRepository is the interface which needs to be implemented by the owner 
// of a policy repository.
type PolicyRepository interface {
	GetRevision() uint64
	GetPolicyCache() PolicyCache
	RLock()
	RUnlock()
	GetSelectorCache() SelectorCache
}

type PolicyCache interface {
	UpdatePolicy(*identity.Identity) error
	Lookup(*identity.Identity) SelectorPolicy
}

type SelectorCache interface {
	RemoveSelectors(CachedSelectorSlice, CachedSelectionUser)
	RemoveSelector(CachedSelector, CachedSelectionUser)
	ChangeUser(CachedSelector, CachedSelectionUser, CachedSelectionUser)
	AddIdentitySelector(CachedSelectionUser, api.EndpointSelector) (CachedSelector, bool)
	AddFQDNSelector(CachedSelectionUser, api.FQDNSelector) (CachedSelector, bool)
}

type PolicyL4Filter interface {
	L7ParserType() string
	IsIngress() bool
	GetPort() int
	GetProtocol() api.L4Proto
	GetL7RulesPerEp() L7DataMap
	GetL7RulesPerEpCopy() L7DataMap
	IsRedirect() bool

	Detach(SelectorCache)
	Attach(L4Policy)
	MatchesLabels(labels labels.LabelArray) bool

	GetRuleLabels() labels.LabelArrayList
	SetRuleLabels(labels.LabelArrayList)
	MarshalIndent() string

	CacheIdentitySelector(api.EndpointSelector, SelectorCache) CachedSelector

	IdentitySelectionUpdated(CachedSelector, []identity.NumericIdentity, []identity.NumericIdentity, []identity.NumericIdentity)
	ToKeys(trafficdirection.TrafficDirection) PolicyKeySlice

	AllowsAllAtL3() bool
	SetAllowsAllAtL3(bool)
	SetCachedSelectors(CachedSelectorSlice)
	GetCachedSelectors() CachedSelectorSlice
	SetL7ParserType(parser string)

	MergeCachedSelectors(PolicyL4Filter, SelectorCache)
}

type L4Policy interface {
	GetIngressPolicies() L4PolicyMap
	GetEgressPolicies() L4PolicyMap

	GetRevision() uint64
}

type L4PolicyMap interface {
	Detach(SelectorCache)
	Attach(L4Policy)

	GetMap() map[string]PolicyL4Filter
}

type L7DataMap map[CachedSelector]api.L7Rules

// CachedSelector represents an identity selector owned by the selector cache
type CachedSelector interface {
	// GetSelections returns the cached set of numeric identities
	// selected by the CachedSelector.  The retuned slice must NOT
	// be modified, as it is shared among multiple users.
	GetSelections() []identity.NumericIdentity

	// Selects return 'true' if the CachedSelector selects the given
	// numeric identity.
	Selects(nid identity.NumericIdentity) bool

	// IsWildcard returns true if the endpoint selector selects
	// all endpoints.
	IsWildcard() bool

	// String returns the string representation of this selector.
	// Used as a map key.
	String() string
}

// CachedSelectorSlice is a slice of CachedSelectors that can be sorted.
type CachedSelectorSlice []CachedSelector

func (s CachedSelectorSlice) Len() int      { return len(s) }
func (s CachedSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s CachedSelectorSlice) Less(i, j int) bool {
	return strings.Compare(s[i].String(), s[j].String()) < 0
}

// SelectsAllEndpoints returns whether the CachedSelectorSlice selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// slice.
func (s CachedSelectorSlice) SelectsAllEndpoints() bool {
	for _, selector := range s {
		if selector.IsWildcard() {
			return true
		}
	}
	return false
}

// Insert in a sorted order? Returns true if inserted, false if cs was already in
func (s *CachedSelectorSlice) Insert(cs CachedSelector) bool {
	for _, selector := range *s {
		if selector == cs {
			return false
		}
	}
	*s = append(*s, cs)
	return true
}


type CachedSelectionUser interface {
	// IdentitySelectionUpdated implementations MUST NOT call back
	// to selector cache while executing this function!
	//
	// The caller is responsible for making sure the same identity is not
	// present in both 'added' and 'deleted'.
	IdentitySelectionUpdated(selector CachedSelector, selections, added, deleted []identity.NumericIdentity)
}

type PolicyKey interface {
	GetIdentity() uint32
	GetDestPort() uint16
	GetNexthdr() uint8
	GetTrafficDirection() uint8
}

type PolicyKeySlice []PolicyKey

func (pk PolicyKeySlice) Append(key PolicyKey) {
	pk = append(pk, key)
}
