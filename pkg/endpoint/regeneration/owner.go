// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package regeneration

import (
	"context"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// Owner is the interface defines the requirements for anybody owning policies.
type Owner interface {
	// QueueEndpointBuild puts the given endpoint in the processing queue
	QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error)

	// GetCompilationLock returns the mutex responsible for synchronizing compilation
	// of BPF programs.
	GetCompilationLock() *lock.RWMutex

	// GetCIDRPrefixLengths returns the sorted list of unique prefix lengths used
	// by CIDR policies.
	GetCIDRPrefixLengths() (s6, s4 []int)

	// SendNotification is called to emit an agent notification
	SendNotification(msg monitorAPI.AgentNotifyMessage) error

	// Datapath returns a reference to the datapath implementation.
	Datapath() datapath.Datapath

	// GetDNSRules creates a fresh copy of DNS rules that can be used when
	// endpoint is restored on a restart.
	// The endpoint lock must not be held while calling this function.
	GetDNSRules(epID uint16) restore.DNSRules

	// RemoveRestoredDNSRules removes any restored DNS rules for
	// this endpoint from the DNS proxy.
	RemoveRestoredDNSRules(epID uint16)
}

// EndpointInfoSource returns information about an endpoint being proxied.
// The read lock must be held when calling any method.
type EndpointInfoSource interface {
	GetID() uint64
	GetIPv4Address() string
	GetIPv6Address() string
	GetIdentity() identity.NumericIdentity
	GetLabels() []string
	HasSidecarProxy() bool
	ConntrackName() string
	ConntrackNameLocked() string
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
