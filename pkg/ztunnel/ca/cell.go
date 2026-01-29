// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ca

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

var Cell = cell.Module(
	"ztunnel-ca",
	"zTunnel built-in certificate authority server",
	cell.Provide(NewServer),
)

type caServerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	EPManager endpointmanager.EndpointManager
	Config    config.Config
}

// NewServer creates a new CA server if zTunnel is enabled and SPIRE is not.
// When SPIRE is enabled, zTunnel obtains certificates directly from SPIRE,
// so the built-in CA server is not needed.
func NewServer(params caServerParams) *Server {
	// Don't start CA server if zTunnel is disabled or SPIRE is enabled
	if !params.Config.EnableZTunnel || params.Config.EnableSPIRE {
		return nil
	}

	server := newServer(
		params.Logger,
		params.EPManager,
		params.Config.CAUnixAddr,
	)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			if err := server.Serve(); err != nil {
				params.Logger.Error("failed to start zTunnel CA server", logfields.Error, err)
				return err
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			server.GracefulStop()
			return nil
		},
	})

	return server
}
