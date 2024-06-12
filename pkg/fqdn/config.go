// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
)

// Config is a simple configuration structure to set how pkg/fqdn subcomponents
// behave.
type Config struct {
	// MinTTL is the time used by the poller to cache information.
	MinTTL int

	// Cache is where the poller stores DNS data used to generate rules.
	// When set to nil, it uses fqdn.DefaultDNSCache, a global cache instance.
	Cache *DNSCache

	// GetEndpointsDNSInfo is a function that returns a list of fqdn-relevant fields from all Endpoints known to the agent.
	// The endpoint's DNSHistory and DNSZombies are used as part of the garbage collection and restoration processes.
	//
	// Optional parameter endpointID will cause this function to only return the endpoint with the specified ID.
	GetEndpointsDNSInfo func(endpointID string) []EndpointDNSInfo

	IPCache IPCache

	// IdentityAllocator will be used to pre-allocate identities when a new selector
	// is registered
	IdentityAllocator IdentityAllocator
}

type EndpointDNSInfo struct {
	ID         string
	ID64       int64
	DNSHistory *DNSCache
	DNSZombies *DNSZombieMappings
}

type IPCache interface {
	UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64)
	RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64)
	WaitForRevision(rev uint64)
}

type IdentityAllocator interface {
	AllocateLocalIdentity(lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated bool, err error)
	Release(ctx context.Context, id *identity.Identity, notifyOwner bool) (released bool, err error)
}
