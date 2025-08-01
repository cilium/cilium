// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bootstrap

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/lookup"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/fqdn/service"
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

	Lifecycle          cell.Lifecycle
	Logger             *slog.Logger
	FQDNConfig         service.FQDNConfig
	DNSRequestHandler  messagehandler.DNSMessageHandler
	ProxyLookupHandler lookup.ProxyLookupHandler
}

// newDNSProxy initializes the DNS l7 proxy.
func newDNSProxy(params dnsProxyParams) (proxy.DNSProxier, error) {
	re.Resize(params.Logger, option.Config.FQDNRegexCompileLRUSize)

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
		EnableDNSCompression:   params.FQDNConfig.ToFQDNsEnableDNSCompression,
		MaxRestoreDNSIPs:       params.FQDNConfig.DNSMaxIPsPerRestoredRule,
		ConcurrencyLimit:       option.Config.DNSProxyConcurrencyLimit,
		ConcurrencyGracePeriod: params.FQDNConfig.DNSProxyConcurrencyProcessingGracePeriod,
		RejectReply:            option.Config.FQDNRejectResponse,
	}

	proxy := dnsproxy.NewDNSProxy(
		dnsProxyConfig,
		params.ProxyLookupHandler,
		params.DNSRequestHandler.NotifyOnDNSMsg)

	return proxy, nil
}
