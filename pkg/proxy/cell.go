// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"fmt"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/proxy/logger/endpoint"
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
	cell.ProvidePrivate(endpoint.NewEndpointInfoRegistry),
)

type proxyParams struct {
	cell.In

	Lifecycle            cell.Lifecycle
	IPCache              *ipcache.IPCache
	Datapath             datapath.Datapath
	EndpointInfoRegistry logger.EndpointInfoRegistry
	MonitorAgent         monitoragent.Agent
}

func newProxy(params proxyParams) (*Proxy, error) {
	if !option.Config.EnableL7Proxy {
		log.Info("L7 proxies are disabled")
		if option.Config.EnableEnvoyConfig {
			log.Warningf("%s is not functional when L7 proxies are disabled", option.EnableEnvoyConfig)
		}
		return nil, nil
	}

	configureProxyLogger(params.EndpointInfoRegistry, params.MonitorAgent, option.Config.AgentLabels)

	// FIXME: Make the port range configurable.
	p := createProxy(10000, 20000, option.Config.RunDir, params.Datapath, params.IPCache, params.EndpointInfoRegistry)

	triggerDone := make(chan struct{})

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(startContext cell.HookContext) (err error) {
			p.proxyPortsTrigger, err = trigger.NewTrigger(trigger.Parameters{
				MinInterval:  10 * time.Second,
				TriggerFunc:  p.storeProxyPorts,
				ShutdownFunc: func() { close(triggerDone) },
			})
			if err != nil {
				return fmt.Errorf("failed to create proxy ports trigger: %w", err)
			}

			xdsServer, err := envoy.StartXDSServer(p.ipcache, envoy.GetSocketDir(p.runDir))
			if err != nil {
				return fmt.Errorf("failed to start Envoy xDS server: %w", err)
			}
			p.XDSServer = xdsServer

			accessLogServer, err := envoy.StartAccessLogServer(envoy.GetSocketDir(p.runDir), p.XDSServer)
			if err != nil {
				return fmt.Errorf("failed to start Envoy AccessLog server: %w", err)
			}
			p.accessLogServer = accessLogServer

			return nil
		},
		OnStop: func(stopContext cell.HookContext) error {
			p.proxyPortsTrigger.Shutdown()
			<-triggerDone

			if p.XDSServer != nil {
				p.XDSServer.Stop()
			}
			if p.accessLogServer != nil {
				p.accessLogServer.Stop()
			}
			return nil
		},
	})

	return p, nil
}

func configureProxyLogger(eir logger.EndpointInfoRegistry, monitorAgent monitoragent.Agent, agentLabels []string) {
	logger.SetEndpointInfoRegistry(eir)
	logger.SetNotifier(logger.NewMonitorAgentLogRecordNotifier(monitorAgent))

	if len(agentLabels) > 0 {
		logger.SetMetadata(agentLabels)
	}
}
