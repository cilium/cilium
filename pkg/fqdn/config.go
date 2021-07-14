// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package fqdn

import (
	"context"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/api"
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
	UpdateSelectors func(ctx context.Context, selectorsWithIPs map[api.FQDNSelector][]net.IP, selectorsWithoutIPs []api.FQDNSelector) (*sync.WaitGroup, map[string]*identity.Identity, error)
}
