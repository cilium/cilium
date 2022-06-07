// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"net"

	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// EndpointInfoSource returns information about an endpoint being proxied.
// The read lock must be held when calling any method.
type EndpointInfoSource interface {
	GetID() uint64
	GetIPv4Address() string
	GetIPv6Address() string
	GetIdentityLocked() identity.NumericIdentity
	GetLabels() []string
	HasSidecarProxy() bool
	// ConntrackName assumes that the caller has *not* acquired any mutexes
	// that may be associated with this EndpointInfoSource. It is (unfortunately)
	// up to the caller to know when to use this vs. ConntrackNameLocked, which
	// assumes that the caller has acquired any needed mutexes of the
	// implementation.
	ConntrackName() string
	ConntrackNameLocked() string
	GetNamedPortLocked(ingress bool, name string, proto uint8) uint16
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

	// OnDNSPolicyUpdateLocked is called when the Endpoint's DNS policy has been updated.
	// 'rules' is a fresh copy of the DNS rules passed to the callee.
	OnDNSPolicyUpdateLocked(rules restore.DNSRules)
}

// EndpointInfoRegistry provides endpoint information lookup by endpoint IP
// address.
type EndpointInfoRegistry interface {
	// FillEndpointInfo resolves the labels of the specified identity if known locally.
	// If 'id' is passed as zero, will locate the EP by 'ip', and also fill info.ID, if found.
	// Fills in the following info member fields:
	//  - info.IPv4           (if 'ip' is IPv4)
	//  - info.IPv6           (if 'ip' is not IPv4)
	//  - info.Identity       (defaults to WORLD if not known)
	//  - info.Labels         (only if identity is found)
	FillEndpointInfo(info *accesslog.EndpointInfo, ip net.IP, id identity.NumericIdentity)
}
