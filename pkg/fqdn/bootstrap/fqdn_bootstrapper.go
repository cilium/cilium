// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
)

type FQDNProxyBootstrapper interface {
	BootstrapFQDN(possibleEndpoints map[uint16]*endpoint.Endpoint, preCachePath string) error
	UpdateDNSDatapathRules(ctx context.Context) error
	CompleteBootstrap()
	Cleanup()
}

type fqdnProxyBootstrapper struct {
	ctx               context.Context
	logger            *slog.Logger
	nameManager       namemanager.NameManager
	proxyInstance     defaultdns.Proxy
	proxyPorts        *proxy.Proxy
	policyRepo        policy.PolicyRepository
	ipcache           *ipcache.IPCache
	endpointManager   endpointmanager.EndpointManager
	dnsRequestHandler DNSRequestHandler
}

var _ FQDNProxyBootstrapper = (*fqdnProxyBootstrapper)(nil)

// bootstrapFQDN initializes the toFQDNs related subsystems: dnsNameManager and the DNS proxy.
// dnsNameManager will use the default resolver and, implicitly, the
// default DNS cache. The proxy binds to all interfaces, and uses the
// configured DNS proxy port (this may be 0 and so OS-assigned).
func (b *fqdnProxyBootstrapper) BootstrapFQDN(possibleEndpoints map[uint16]*endpoint.Endpoint, preCachePath string) (err error) {
	b.policyRepo.GetSelectorCache().SetLocalIdentityNotifier(b.nameManager)

	// Controller to cleanup TTL expired entries from the DNS policies.
	b.nameManager.StartGC(b.ctx)

	// restore the global DNS cache state
	b.nameManager.RestoreCache(preCachePath, possibleEndpoints)

	// Do not start the proxy in dry mode or if L7 proxy is disabled.
	// The proxy would not get any traffic in the dry mode anyway, and some of the socket
	// operations require privileges not available in all unit tests.
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil
	}

	// A configured proxy wantPort takes precedence over using the previous wantPort.
	wantPort := uint16(option.Config.ToFQDNsProxyPort)
	if wantPort == 0 {
		var isStatic bool
		// Try reuse previous DNS proxy port number
		wantPort, isStatic, _ = b.proxyPorts.GetProxyPort(proxytypes.DNSProxyName)

		if _, alreadyOpen := b.proxyPorts.GetOpenLocalPorts()[wantPort]; !isStatic && alreadyOpen {
			wantPort = 0
			b.logger.Info("Unable re-use old DNS proxy port as it is already in use", logfields.Port, wantPort)
		}
	}

	if err := re.InitRegexCompileLRU(option.Config.FQDNRegexCompileLRUSize); err != nil {
		return fmt.Errorf("could not initialize regex LRU cache: %w", err)
	}
	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Address:                "",
		Port:                   wantPort,
		IPv4:                   option.Config.EnableIPv4,
		IPv6:                   option.Config.EnableIPv6,
		EnableDNSCompression:   option.Config.ToFQDNsEnableDNSCompression,
		MaxRestoreDNSIPs:       option.Config.DNSMaxIPsPerRestoredRule,
		ConcurrencyLimit:       option.Config.DNSProxyConcurrencyLimit,
		ConcurrencyGracePeriod: option.Config.DNSProxyConcurrencyProcessingGracePeriod,
	}
	dnsProxy := dnsproxy.NewDNSProxy(dnsProxyConfig, b.lookupEPByIP, b.ipcache.LookupSecIDByIP, b.ipcache.LookupByIdentity, b.dnsRequestHandler.NotifyOnDNSMsg)
	b.proxyInstance.Set(dnsProxy)

	if err := dnsProxy.Listen(); err != nil {
		return fmt.Errorf("error opening dns proxy socket(s): %w", err)
	}

	if wantPort == dnsProxy.GetBindPort() {
		b.logger.Info("Reusing previous / configured DNS proxy port", logfields.Port, wantPort)
	}

	// Increase the ProxyPort reference count so that it will never get released.
	if err := b.proxyPorts.SetProxyPort(proxytypes.DNSProxyName, proxytypes.ProxyTypeDNS, dnsProxy.GetBindPort(), false); err != nil {
		// should never happen
		b.logger.Warn("BUG: Failed to increase DNS proxy port refcount", logfields.Error, err)
	}

	dnsProxy.SetRejectReply(option.Config.FQDNRejectResponse)
	// Restore old rules
	for _, possibleEP := range possibleEndpoints {
		// Upgrades from old ciliums have this nil
		if possibleEP.DNSRules != nil || possibleEP.DNSRulesV2 != nil {
			dnsProxy.RestoreRules(possibleEP)
		}
	}
	return nil
}

// updateDNSDatapathRules updates the DNS proxy iptables rules. Must be
// called after iptables has been initialized, and only after
// successful bootstrapFQDN().
func (b *fqdnProxyBootstrapper) UpdateDNSDatapathRules(ctx context.Context) error {
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil
	}

	return b.proxyPorts.AckProxyPort(ctx, proxytypes.DNSProxyName)
}

// lookupEPByIP returns the endpoint that this IP belongs to
func (b *fqdnProxyBootstrapper) lookupEPByIP(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	if e := b.endpointManager.LookupIP(endpointAddr); e != nil {
		return e, e.IsHost(), nil
	}

	if node.IsNodeIP(endpointAddr) != "" {
		if e := b.endpointManager.GetHostEndpoint(); e != nil {
			return e, true, nil
		} else {
			return nil, true, errors.New("host endpoint has not been created yet")
		}
	}

	return nil, false, fmt.Errorf("cannot find endpoint with IP %s", endpointAddr)
}

func (b *fqdnProxyBootstrapper) CompleteBootstrap() {
	b.nameManager.CompleteBootstrap()
}

func (b *fqdnProxyBootstrapper) Cleanup() {
	if p := b.proxyInstance.Get(); p != nil {
		p.Cleanup()
	}
}
