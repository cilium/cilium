// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bootstrap

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
)

type FQDNProxyBootstrapper interface {
	BootstrapFQDN(possibleEndpoints map[uint16]*endpoint.Endpoint)
}

type fqdnProxyBootstrapperParams struct {
	cell.In

	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Logger    *slog.Logger

	ProxyPorts        *proxyports.ProxyPorts
	DNSProxy          proxy.DNSProxier
	Health            cell.Health
	DNSRequestHandler messagehandler.DNSMessageHandler
}

type fqdnProxyBootstrapper struct {
	logger *slog.Logger

	proxy      proxy.DNSProxier
	proxyPorts *proxyports.ProxyPorts
	handler    messagehandler.DNSMessageHandler

	restored chan struct{}
}

// newFQDNProxyBootstrapper handles initializing the DNS proxy in concert with the daemon.
func newFQDNProxyBootstrapper(params fqdnProxyBootstrapperParams) FQDNProxyBootstrapper {

	b := &fqdnProxyBootstrapper{
		logger: params.Logger,

		proxy:      params.DNSProxy,
		proxyPorts: params.ProxyPorts,
		handler:    params.DNSRequestHandler,

		restored: make(chan struct{}),
	}

	// Do not start the proxy in dry mode or if L7 proxy is disabled.
	// The proxy would not get any traffic in the dry mode anyway, and some of the socket
	// operations require privileges not available in all unit tests.
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return b
	}

	params.JobGroup.Add(job.OneShot("proxy-bootstrapper", b.startProxy, job.WithShutdown()))

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(_ cell.HookContext) error {
			b.proxy.Cleanup()
			return nil
		},
	})

	return b
}

var _ FQDNProxyBootstrapper = (*fqdnProxyBootstrapper)(nil)

// BootstrapFQDN restores per-endpoint cached FQDN L7 rules to the proxy,
// so it may immediately listen and start serving.
func (b *fqdnProxyBootstrapper) BootstrapFQDN(possibleEndpoints map[uint16]*endpoint.Endpoint) {
	// was proxy disabled?
	if b.proxy == nil {
		return
	}

	// Restore old rules
	eps := make([]uint16, 0, len(possibleEndpoints))
	for _, possibleEP := range possibleEndpoints {
		// Upgrades from old ciliums have this nil
		if possibleEP.DNSRules != nil || possibleEP.DNSRulesV2 != nil {
			b.proxy.RestoreRules(possibleEP)
			eps = append(eps, possibleEP.ID)
		}
	}
	if len(eps) > 0 {
		b.logger.Info("Loaded DNS L7 rules for restored endpoints", logfields.Endpoints, eps)
	}

	close(b.restored)
}

// startProxy waits for cached endpoint state to be loaded, then starts
// the DNS proxy.
func (b *fqdnProxyBootstrapper) startProxy(ctx context.Context, health cell.Health) error {
	// Wait for proxy ports to be loaded from disk
	select {
	case <-b.proxyPorts.RestoreComplete():
	case <-ctx.Done():
		return nil
	}

	// wait for restore rules to be provided
	select {
	case <-b.restored:
	case <-ctx.Done():
		return nil
	}

	// A configured proxy wantPort takes precedence over using the previous wantPort.
	// An existing (restored-from-disk) port is used on a best-effort basis
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

	if err := b.proxy.Listen(wantPort); err != nil {
		return fmt.Errorf("error opening dns proxy socket(s): %w", err)
	}
	bindPort := b.proxy.GetBindPort()

	if wantPort == bindPort {
		b.logger.Info("Reusing previous / configured DNS proxy port", logfields.Port, wantPort)
	}

	// Increase the ProxyPort reference count so that it will never get released.
	if err := b.proxyPorts.SetProxyPort(proxytypes.DNSProxyName, proxytypes.ProxyTypeDNS, bindPort, false); err != nil {
		// should never happen
		b.logger.Warn("BUG: Failed to increase DNS proxy port refcount", logfields.Error, err)
	}

	// tell the message handler about the bind port, so it can correctly update statistics
	b.handler.SetBindPort(b.proxy.GetBindPort())

	// Set up iptables rules.
	if err := b.proxyPorts.AckProxyPortWithReference(ctx, proxytypes.DNSProxyName); err != nil {
		return fmt.Errorf("failed to ack DNS proxy port: %w", err)
	}

	health.OK(fmt.Sprintf("DNS proxy successfully initialized on port %d", bindPort))
	return nil
}
