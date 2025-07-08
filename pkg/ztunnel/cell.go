// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
)

// Cell starts an xDS server scoped specifically for zTunnel integration.
var Cell = cell.Module(
	"ztunnel",
	"ztunnel certificate authority and control plane",
	cell.Provide(newZTunnelXDSServer),
	cell.Config(Config{}),
	cell.Invoke(func(*xds.Server) {}),
)

type Config struct {
	EnableZTunnel bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
}

type xdsServerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	EPLookup  endpointmanager.EndpointsLookup
	Config    Config
}

func newZTunnelXDSServer(params xdsServerParams) (*xds.Server, error) {
	if !params.Config.EnableZTunnel {
		return nil, nil
	}

	server, err := xds.NewServer(params.Logger, params.EPLookup)
	if err != nil {
		return nil, fmt.Errorf("failed to create ztunnel gRPC server: %w", err)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			if err := server.Serve(); err != nil {
				return fmt.Errorf("failed to start Envoy xDS server: %w", err)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			server.GracefulStop()
			return nil
		},
	})

	return server, nil
}
