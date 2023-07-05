// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/option"
)

// Cell initializes and manages the Envoy proxy and its control-plane components like xDS- and accesslog server.
// It is used to provide support for Ingress, GatewayAPI and L7 network policies (e.g. HTTP).
var Cell = cell.Module(
	"envoy-proxy",
	"Envoy proxy and control-plane",

	cell.Provide(newEnvoyXDSServer),
	cell.Invoke(registerEnvoyAccessLogServer),
)

type xdsServerParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	IPCache   *ipcache.IPCache
}

func newEnvoyXDSServer(params xdsServerParams) (XDSServer, error) {
	xdsServer, err := newXDSServer(GetSocketDir(option.Config.RunDir), params.IPCache)
	if err != nil {
		return nil, fmt.Errorf("failed to create Envoy xDS server: %w", err)
	}

	if !option.Config.EnableL7Proxy {
		log.Debug("L7 proxies are disabled - not starting Envoy xDS server")
		return xdsServer, nil
	}

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(startContext hive.HookContext) error {
			if err := xdsServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy xDS server: %w", err)
			}
			return nil
		},
		OnStop: func(stopContext hive.HookContext) error {
			xdsServer.stop()
			return nil
		},
	})

	return xdsServer, nil
}

type accessLogServerParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	XdsServer XDSServer
}

func registerEnvoyAccessLogServer(params accessLogServerParams) {
	if !option.Config.EnableL7Proxy {
		log.Debug("L7 proxies are disabled - not starting Envoy AccessLog server")
		return
	}

	accessLogServer := newAccessLogServer(GetSocketDir(option.Config.RunDir), params.XdsServer)

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(startContext hive.HookContext) error {
			if err := accessLogServer.start(); err != nil {
				return fmt.Errorf("failed to start Envoy AccessLog server: %w", err)
			}
			return nil
		},
		OnStop: func(stopContext hive.HookContext) error {
			accessLogServer.stop()
			return nil
		},
	})
}
