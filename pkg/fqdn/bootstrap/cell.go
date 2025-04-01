// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bootstrap

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// Cell provides the FQDN bootstrap functionality
var Cell = cell.Module(
	"fqdn-bootstrap",
	"Bootstraps the FQDN policy subsystem",

	cell.Provide(newFQDNProxyBootstrapper),
	cell.Provide(newDNSRequestHandler),
)

type fqdnProxyBootstrapperParams struct {
	cell.In

	Lifecycle         cell.Lifecycle
	Logger            *slog.Logger
	NameManager       namemanager.NameManager
	ProxyInstance     defaultdns.Proxy
	ProxyPorts        *proxy.Proxy
	PolicyRepo        policy.PolicyRepository
	IPCache           *ipcache.IPCache
	EndpointManager   endpointmanager.EndpointManager
	DNSRequestHandler DNSRequestHandler
}

func newFQDNProxyBootstrapper(params fqdnProxyBootstrapperParams) FQDNProxyBootstrapper {
	ctx, cancelCtx := context.WithCancel(context.Background())

	bootstrapper := &fqdnProxyBootstrapper{
		ctx:               ctx,
		logger:            params.Logger,
		nameManager:       params.NameManager,
		proxyInstance:     params.ProxyInstance,
		proxyPorts:        params.ProxyPorts,
		policyRepo:        params.PolicyRepo,
		ipcache:           params.IPCache,
		endpointManager:   params.EndpointManager,
		dnsRequestHandler: params.DNSRequestHandler,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hookContext cell.HookContext) error {
			cancelCtx()
			return nil
		},
	})

	return bootstrapper
}

type dnsRequestHandlerParams struct {
	cell.In

	Lifecycle         cell.Lifecycle
	Logger            *slog.Logger
	NameManager       namemanager.NameManager
	ProxyInstance     defaultdns.Proxy
	ProxyAccessLogger accesslog.ProxyAccessLogger
}

func newDNSRequestHandler(params dnsRequestHandlerParams) DNSRequestHandler {
	ctx, cancelCtx := context.WithCancel(context.Background())

	handler := &dnsRequestHandler{
		ctx:               ctx,
		logger:            params.Logger,
		nameManager:       params.NameManager,
		proxyInstance:     params.ProxyInstance,
		proxyAccessLogger: params.ProxyAccessLogger,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hookContext cell.HookContext) error {
			cancelCtx()
			return nil
		},
	})

	return handler
}
