// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

var Cell = cell.Module(
	"ztunnel-xds",
	"ztunnel certificate authority and control plane",
	cell.Invoke(NewServer),
)

type xdsServerParams struct {
	cell.In

	Lifecycle  cell.Lifecycle
	Logger     *slog.Logger
	EPManager  endpointmanager.EndpointManager
	K8sWatcher *watchers.K8sWatcher
	Config     config.Config
}

func NewServer(params xdsServerParams) (*Server, error) {
	if !params.Config.EnableZTunnel {
		return nil, nil
	}

	server, err := newServer(params.Logger, params.EPManager, params.K8sWatcher.GetK8sCiliumEndpointsWatcher())
	if err != nil {
		return nil, fmt.Errorf("failed to create ztunnel gRPC server: %w", err)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			if err := server.Serve(); err != nil {
				params.Logger.Error("failed to start ztunnel gRPC server", logfields.Error, err)
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
