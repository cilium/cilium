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

package logger

import (
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

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
	ProxyID(l4 *policy.L4Filter) string
}

// getEndpointInfo returns a consistent snapshot of the given source.
// The source's read lock must not be held.
func getEndpointInfo(source EndpointInfoSource) *accesslog.EndpointInfo {
	source.UnconditionalRLock()
	defer source.RUnlock()
	return &accesslog.EndpointInfo{
		ID:           source.GetID(),
		IPv4:         source.GetIPv4Address(),
		IPv6:         source.GetIPv6Address(),
		Labels:       source.GetLabels(),
		LabelsSHA256: source.GetLabelsSHA(),
		Identity:     uint64(source.GetIdentity()),
	}
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
	UpdateProxyStatistics(l4Protocol string, port uint16, ingress, request bool, verdict accesslog.FlowVerdict)
}

// EndpointInfoRegistry provides endpoint information lookup by endpoint IP
// address.
type EndpointInfoRegistry interface {
	// FillEndpointIdentityByID resolves the labels of the specified identity
	// if known locally and fills in the following info member fields:
	//  - info.Identity
	//  - info.Labels
	//  - info.LabelsSHA256
	// Returns true if found, false if not found.
	FillEndpointIdentityByID(id identity.NumericIdentity, info *accesslog.EndpointInfo) bool

	// FillEndpointIdentityByIP resolves the labels of the endpoint with the
	// specified IP if known locally and fills in the following info member
	// fields:
	//  - info.ID
	//  - info.Identity
	//  - info.Labels
	//  - info.LabelsSHA256
	// Returns true if found, false if not found.
	FillEndpointIdentityByIP(ip net.IP, info *accesslog.EndpointInfo) bool
}
