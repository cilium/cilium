// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the standalone dns proxy grpc server.
var Cell = cell.Module(
	"sdp-grpc-server",
	"Provides the standalone dns proxy grpc server",

	cell.Config(defaultConfig),
	cell.Provide(newServer),
)

type serverParams struct {
	cell.In

	Lifecycle         cell.Lifecycle
	Logger            *slog.Logger
	EndpointManager   endpointmanager.EndpointManager
	DNSRequestHandler messagehandler.DNSRequestHandler
	IPCache           *ipcache.IPCache
	JobGroup          job.Group
}

func newServer(params serverParams, config FQDNConfig) *FQDNDataServer {
	srv := NewServer(params.EndpointManager, params.DNSRequestHandler, config.ToFQDNsServerPort, params.Logger)

	if !config.EnableStandaloneDNSProxy {
		return srv
	}

	if !option.Config.EnableL7Proxy {
		srv.log.Error("Standalone DNS proxy requires L7 proxy to be enabled")
		return srv
	}

	if option.Config.ToFQDNsProxyPort == 0 || config.ToFQDNsServerPort == 0 {
		srv.log.Error("Standalone DNS proxy requires a valid port number to be set")
		return srv
	}

	params.IPCache.AddListener(srv)

	params.JobGroup.Add(job.OneShot("sdp-grpc-server", func(ctx context.Context, _ cell.Health) error {
		return srv.Start()
	},
		job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}),
		job.WithShutdown()),
	)

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hookContext cell.HookContext) error {
			srv.Stop()
			return nil
		},
	})

	return srv
}

type FQDNConfig struct {
	// EnableStandaloneDNSProxy is the option to enable standalone DNS proxy
	EnableStandaloneDNSProxy bool

	// ToFQDNsServerPort is the user-configured global, Standalone DNS proxy gRPC server port
	ToFQDNsServerPort int
}

var defaultConfig = FQDNConfig{
	EnableStandaloneDNSProxy: false,
	ToFQDNsServerPort:        40045,
}

func (def FQDNConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableStandaloneDNSProxy, def.EnableStandaloneDNSProxy, "Enables standalone DNS proxy")
	flags.Int(option.ToFQDNsServerPort, def.ToFQDNsServerPort, "Global port on which the gRPC server for standalone DNS proxy should listen")
}
