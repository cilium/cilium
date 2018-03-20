// Copyright 2018 Authors of Cilium
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

package envoy

import "github.com/cilium/cilium/pkg/envoy/xds"

const (
	// ListenerTypeURL is the type URL of Listener resources.
	ListenerTypeURL = "type.googleapis.com/envoy.api.v2.Listener"

	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL = "type.googleapis.com/cilium.NetworkPolicy"

	// NetworkPolicyHostsTypeURL is the type URL of NetworkPolicyHosts resources.
	NetworkPolicyHostsTypeURL = "type.googleapis.com/cilium.NetworkPolicyHosts"
)

var (
	// NetworkPolicyCache is the global cache of resources of type
	// NetworkPolicy. Resources in this cache must have the
	// NetworkPolicyTypeURL type URL.
	NetworkPolicyCache = xds.NewCache()

	// AckingNetworkPolicyMutator handles acknowledgements of NetworkPolicy
	// resource updates.
	AckingNetworkPolicyMutator = xds.NewAckingResourceMutatorWrapper(NetworkPolicyCache, xds.IstioNodeToIP)

	// NetworkPolicyHostsCache is the global cache of resources of type
	// NetworkPolicyHosts. Resources in this cache must have the
	// NetworkPolicyHostsTypeURL type URL.
	NetworkPolicyHostsCache = xds.NewCache()
)
