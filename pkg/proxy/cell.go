// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
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
	cell.ProvidePrivate(endpoint.NewEndpointInfoRegistry),
)

type proxyParams struct {
	cell.In

	IPCache              *ipcache.IPCache
	Datapath             datapath.Datapath
	EndpointInfoRegistry logger.EndpointInfoRegistry
	MonitorAgent         monitoragent.Agent
	XdsServer            envoy.XDSServer
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

	// FIXME: Make the port range configurable.
	return createProxy(10000, 20000, option.Config.RunDir, params.Datapath, params.EndpointInfoRegistry, params.XdsServer)
}

func configureProxyLogger(eir logger.EndpointInfoRegistry, monitorAgent monitoragent.Agent, agentLabels []string) {
	logger.SetEndpointInfoRegistry(eir)
	logger.SetNotifier(logger.NewMonitorAgentLogRecordNotifier(monitorAgent))

	if len(agentLabels) > 0 {
		logger.SetMetadata(agentLabels)
	}
}
