// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive/cell"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/proxy/logger/endpoint"
)

// Cell provides the L7 Proxy which provides support for L7 network policies.
// It is manages the different L7 proxies (Envoy, CoreDNS, ...) and the
// traffic redirection to them.
var Cell = cell.Module(
	"l7-proxy",
	"L7 Proxy provides support for L7 network policies",

	cell.Provide(func() ProxyConfig { return DefaultProxyConfig }),

	cell.Provide(newProxy),
	cell.Provide(newEnvoyProxyIntegration),
	cell.Provide(newDNSProxyIntegration),
	cell.ProvidePrivate(endpoint.NewEndpointInfoRegistry),
)

type ProxyConfig struct {
	MinPort, MaxPort uint16
	DNSProxyPort     uint16
}

var DefaultProxyConfig = ProxyConfig{
	MinPort: 10000,
	MaxPort: 20000,
	// The default value for the DNS proxy port is set to 0 to allocate a random
	// port.
	DNSProxyPort: 0,
}

type proxyParams struct {
	cell.In

	Datapath              datapath.Datapath
	EndpointInfoRegistry  logger.EndpointInfoRegistry
	MonitorAgent          monitoragent.Agent
	EnvoyProxyIntegration *envoyProxyIntegration
	DNSProxyIntegration   *dnsProxyIntegration
	XdsServer             envoy.XDSServer
}

func newProxy(params proxyParams, cfg ProxyConfig) *Proxy {
	if !option.Config.EnableL7Proxy {
		log.Info("L7 proxies are disabled")
		if option.Config.EnableEnvoyConfig {
			log.Warningf("%s is not functional when L7 proxies are disabled", option.EnableEnvoyConfig)
		}
		return nil
	}

	configureProxyLogger(params.EndpointInfoRegistry, params.MonitorAgent, option.Config.AgentLabels)

	return createProxy(cfg.MinPort, cfg.MaxPort, cfg.DNSProxyPort, params.Datapath, params.EnvoyProxyIntegration, params.DNSProxyIntegration, params.XdsServer)
}

type envoyProxyIntegrationParams struct {
	cell.In

	Datapath    datapath.Datapath
	XdsServer   envoy.XDSServer
	AdminClient *envoy.EnvoyAdminClient
}

func newEnvoyProxyIntegration(params envoyProxyIntegrationParams) *envoyProxyIntegration {
	if !option.Config.EnableL7Proxy {
		return nil
	}

	return &envoyProxyIntegration{
		xdsServer:   params.XdsServer,
		datapath:    params.Datapath,
		adminClient: params.AdminClient,
	}
}

func newDNSProxyIntegration() *dnsProxyIntegration {
	if !option.Config.EnableL7Proxy {
		return nil
	}

	return &dnsProxyIntegration{}
}

func configureProxyLogger(eir logger.EndpointInfoRegistry, monitorAgent monitoragent.Agent, agentLabels []string) {
	logger.SetEndpointInfoRegistry(eir)
	logger.SetNotifier(logger.NewMonitorAgentLogRecordNotifier(monitorAgent))

	if len(agentLabels) > 0 {
		logger.SetMetadata(agentLabels)
	}
}
