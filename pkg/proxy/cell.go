// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/controller"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/accesslog/endpoint"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

// Cell provides the L7 Proxy which provides support for L7 network policies.
// It is manages the different L7 proxies (Envoy, CoreDNS, ...) and the
// traffic redirection to them.
var Cell = cell.Module(
	"l7-proxy",
	"L7 Proxy provides support for L7 network policies",

	cell.Provide(newProxy),
	cell.Provide(newEnvoyProxyIntegration),
	cell.Provide(newDNSProxyIntegration),
	cell.ProvidePrivate(endpoint.NewEndpointInfoRegistry),
	cell.Provide(proxyports.NewProxyPorts),
	cell.Config(proxyports.ProxyPortsConfig{}),
	accesslog.Cell,
)

type proxyParams struct {
	cell.In

	Lifecycle             cell.Lifecycle
	Logger                *slog.Logger
	LocalNodeStore        *node.LocalNodeStore
	ProxyPorts            *proxyports.ProxyPorts
	EnvoyProxyIntegration *envoyProxyIntegration
	DNSProxyIntegration   *dnsProxyIntegration
}

func newProxy(params proxyParams) *Proxy {
	if !option.Config.EnableL7Proxy {
		params.Logger.Info("L7 proxies are disabled")
		if option.Config.EnableEnvoyConfig {
			params.Logger.Warn("CiliumEnvoyConfig functionality isn't enabled when L7 proxies are disabled", logfields.Flag, option.EnableEnvoyConfig)
		}
		return nil
	}

	p := createProxy(params.Logger, params.LocalNodeStore, params.ProxyPorts, params.EnvoyProxyIntegration, params.DNSProxyIntegration)

	triggerDone := make(chan struct{})

	controllerManager := controller.NewManager()
	controllerGroup := controller.NewGroup("proxy-ports-allocator")
	controllerName := "proxy-ports-checkpoint"

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			// Restore all proxy ports before we create the trigger to overwrite the
			// file below
			p.proxyPorts.RestoreProxyPorts()

			p.proxyPorts.Trigger, err = trigger.NewTrigger(trigger.Parameters{
				MinInterval: 10 * time.Second,
				TriggerFunc: func(reasons []string) {
					controllerManager.UpdateController(controllerName, controller.ControllerParams{
						Group:    controllerGroup,
						DoFunc:   p.proxyPorts.StoreProxyPorts,
						StopFunc: p.proxyPorts.StoreProxyPorts, // perform one last checkpoint when the controller is removed
					})
				},
				ShutdownFunc: func() {
					controllerManager.RemoveControllerAndWait(controllerName) // waits for StopFunc
					close(triggerDone)
				},
			})
			return err
		},
		OnStop: func(cell.HookContext) error {
			p.proxyPorts.Trigger.Shutdown()
			<-triggerDone
			return nil
		},
	})

	return p
}

type envoyProxyIntegrationParams struct {
	cell.In

	IptablesManager datapath.IptablesManager
	XdsServer       envoy.XDSServer
	AdminClient     *envoy.EnvoyAdminClient
}

func newEnvoyProxyIntegration(params envoyProxyIntegrationParams) *envoyProxyIntegration {
	if !option.Config.EnableL7Proxy {
		return nil
	}

	return &envoyProxyIntegration{
		xdsServer:       params.XdsServer,
		iptablesManager: params.IptablesManager,
		adminClient:     params.AdminClient,
	}
}

func newDNSProxyIntegration(dnsProxy fqdnproxy.DNSProxier, sdpPolicyUpdater *service.FQDNDataServer) *dnsProxyIntegration {
	if !option.Config.EnableL7Proxy {
		return nil
	}

	return &dnsProxyIntegration{
		dnsProxy:         dnsProxy,
		sdpPolicyUpdater: sdpPolicyUpdater,
	}
}
