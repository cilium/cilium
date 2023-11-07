// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"net/netip"
	"sync"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
)

// Config is a simple configuration structure to set how pkg/fqdn subcomponents
// behave.
type Config struct {
	// MinTTL is the time used by the poller to cache information.
	MinTTL int

	// Cache is where the poller stores DNS data used to generate rules.
	// When set to nil, it uses fqdn.DefaultDNSCache, a global cache instance.
	Cache *DNSCache

	// UpdateSelectors is a callback to update the mapping of FQDNSelector to
	// sets of IPs.
	UpdateSelectors func(ctx context.Context, selectorsToIPs map[api.FQDNSelector][]netip.Addr, ipcacheRevision uint64) *sync.WaitGroup

	// GetEndpointsDNSInfo is a function that returns a list of fqdn-relevant fields from all Endpoints known to the agent.
	// The endpoint's DNSHistory and DNSZombies are used as part of the garbage collection and restoration processes.
	GetEndpointsDNSInfo func() []EndpointDNSInfo

	IPCache IPCache
}

type EndpointDNSInfo struct {
	ID         string
	DNSHistory *DNSCache
	DNSZombies *DNSZombieMappings
}

type IPCache interface {
	UpsertPrefixes(prefixes []netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID) uint64
	RemovePrefixes(prefixes []netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID)
}
