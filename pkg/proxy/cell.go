// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
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

	Lifecycle            hive.Lifecycle
	IPCache              *ipcache.IPCache
	Datapath             datapath.Datapath
	EndpointInfoRegistry logger.EndpointInfoRegistry
}

func newProxy(params proxyParams) (*Proxy, error) {
	if !option.Config.EnableL7Proxy {
		log.Info("L7 proxies are disabled")
		if option.Config.EnableEnvoyConfig {
			log.Warningf("%s is not functional when L7 proxies are disabled", option.EnableEnvoyConfig)
		}
		return nil, nil
	}

	configureProxyLogger(params.EndpointInfoRegistry, option.Config.AgentLabels)

	// FIXME: Make the port range configurable.
	proxy := createProxy(10000, 20000, option.Config.RunDir, params.Datapath, params.IPCache, params.EndpointInfoRegistry)

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(startContext hive.HookContext) error {
			proxy.XDSServer = envoy.StartXDSServer(proxy.ipcache, envoy.GetSocketDir(proxy.runDir))
			envoy.StartAccessLogServer(envoy.GetSocketDir(proxy.runDir), proxy.XDSServer)
			return nil
		},
		OnStop: func(stopContext hive.HookContext) error {
			return nil
		},
	})

	return proxy, nil
}

func configureProxyLogger(eir logger.EndpointInfoRegistry, agentLabels []string) {
	logger.SetEndpointInfoRegistry(eir)

	//if params.MonitorAgent != nil {
	//	logger.SetNotifier(params.MonitorAgent)
	//}

	if len(agentLabels) > 0 {
		logger.SetMetadata(agentLabels)
	}
}
