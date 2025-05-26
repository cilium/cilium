// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the DNS L7 proxy
var Cell = cell.Module(
	"dns-proxy",
	"Starts the DNS proxy",

	cell.Provide(newFQDNProxyBootstrapper),
	cell.Provide(newDNSProxy),
)

type dnsProxyParams struct {
	cell.In

	Lifecycle         cell.Lifecycle
	Logger            *slog.Logger
	DNSRequestHandler messagehandler.DNSMessageHandler
	EndpointManager   endpointmanager.EndpointManager
	IPCache           *ipcache.IPCache
	LocalNodeStore    *node.LocalNodeStore
}

// newDNSProxy initializes the DNS l7 proxy.
func newDNSProxy(params dnsProxyParams) (proxy.DNSProxier, error) {
	if err := re.InitRegexCompileLRU(params.Logger, option.Config.FQDNRegexCompileLRUSize); err != nil {
		// can only happen if LRUSize is negative
		return nil, err
	}

	// Do not start the proxy in dry mode or if L7 proxy is disabled.
	// The proxy would not get any traffic in the dry mode anyway, and some of the socket
	// operations require privileges not available in all unit tests.
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil, nil
	}

	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Logger:                 params.Logger,
		Address:                "",
		IPv4:                   option.Config.EnableIPv4,
		IPv6:                   option.Config.EnableIPv6,
		EnableDNSCompression:   option.Config.ToFQDNsEnableDNSCompression,
		MaxRestoreDNSIPs:       option.Config.DNSMaxIPsPerRestoredRule,
		ConcurrencyLimit:       option.Config.DNSProxyConcurrencyLimit,
		ConcurrencyGracePeriod: option.Config.DNSProxyConcurrencyProcessingGracePeriod,
		RejectReply:            option.Config.FQDNRejectResponse,
	}

	proxy := dnsproxy.NewDNSProxy(
		dnsProxyConfig,
		params.IPCache,
		lookupRegisteredEndpointFunc(params.EndpointManager, params.LocalNodeStore),
		params.DNSRequestHandler.NotifyOnDNSMsg)

	return proxy, nil
}

// lookupRegisteredEndpointFunc (returns a function that) looks up the endpoint corresponding
// to a given IP address. It correctly handles *all* IPs belonging to the node, not just that
// of the node endpoint.
func lookupRegisteredEndpointFunc(epm endpointmanager.EndpointManager, lns *node.LocalNodeStore) func(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	return func(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
		if e := epm.LookupIP(endpointAddr); e != nil {
			return e, e.IsHost(), nil
		}

		localNode, err := lns.Get(context.TODO())
		if err != nil {
			return nil, true, fmt.Errorf("local node has not been initialized yet: %w", err)
		}

		if localNode.IsNodeIP(endpointAddr) != "" {
			if e := epm.GetHostEndpoint(); e != nil {
				return e, true, nil
			} else {
				return nil, true, errors.New("host endpoint has not been created yet")
			}
		}

		return nil, false, fmt.Errorf("cannot find endpoint with IP %s", endpointAddr)
	}
}
