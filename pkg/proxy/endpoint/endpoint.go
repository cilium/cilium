// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

// EndpointInfoSource returns information about an endpoint being proxied.
// The read lock must be held when calling any method.
type EndpointInfoSource interface {
	GetPolicyNames() []string
	GetID() uint64
	GetIPv4Address() string
	GetIPv6Address() string
	GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16
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
	UpdateProxyStatistics(proxyType, l4Protocol string, port, proxyPort uint16, ingress, request bool, verdict accesslog.FlowVerdict)

	// GetPolicyVersionHandle returns the selector cache version handle held for Endpoint's
	// desired policy, if any.
	// Must be called with Endpoint's read lock taken.
	GetPolicyVersionHandle() *versioned.VersionHandle

	// GetListenerProxyPort returns the proxy port for the given listener reference.
	// Returns zero if the proxy port does not exist (yet).
	GetListenerProxyPort(listener string) uint16
}
