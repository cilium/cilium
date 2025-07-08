package xds

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

var Cell = cell.Module(
	"ztunnel-xds",
	"ztunnel certificate authority and control plane",
	cell.Provide(NewServer),
	cell.Invoke(NewServer),
)

type xdsServerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	EPLookup  endpointmanager.EndpointsLookup
	Config    config.Config
}

func NewServer(params xdsServerParams) (*Server, error) {
	if !params.Config.EnableZTunnel {
		return nil, nil
	}

	server, err := newServer(params.Logger, params.EPLookup)
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
