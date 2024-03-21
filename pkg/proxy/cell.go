// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/spf13/pflag"

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

	cell.Provide(newProxy),
	cell.Provide(newEnvoyProxyIntegration),
	cell.Provide(newDNSProxyIntegration),
	cell.ProvidePrivate(endpoint.NewEndpointInfoRegistry),
	cell.Config(ProxyConfig{}),
)

type ProxyConfig struct {
	ProxyPortrangeMin uint16
	ProxyPortrangeMax uint16
}

func (r ProxyConfig) Flags(flags *pflag.FlagSet) {
	flags.Uint16("proxy-portrange-min", 10000, "Start of port range that is used to allocate ports for L7 proxies.")
	flags.Uint16("proxy-portrange-max", 20000, "End of port range that is used to allocate ports for L7 proxies.")
}

type proxyParams struct {
	cell.In

	Config                ProxyConfig
	Datapath              datapath.Datapath
	EndpointInfoRegistry  logger.EndpointInfoRegistry
	MonitorAgent          monitoragent.Agent
	EnvoyProxyIntegration *envoyProxyIntegration
	DNSProxyIntegration   *dnsProxyIntegration
}

func newProxy(params proxyParams) *Proxy {
	if !option.Config.EnableL7Proxy {
		log.Info("L7 proxies are disabled")
		if option.Config.EnableEnvoyConfig {
			log.Warningf("%s is not functional when L7 proxies are disabled", option.EnableEnvoyConfig)
		}
		return nil
	}

	configureProxyLogger(params.EndpointInfoRegistry, params.MonitorAgent, option.Config.AgentLabels)

	return createProxy(params.Config.ProxyPortrangeMin, params.Config.ProxyPortrangeMax, params.Datapath, params.EnvoyProxyIntegration, params.DNSProxyIntegration)
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
