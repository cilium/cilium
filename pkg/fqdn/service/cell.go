// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
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

// Cell provides the standalone DNS proxy gRPC server.
// It is responsible for sending the DNS rules and IP cache updates
// to the standalone DNS proxy. It also handles the DNS responses
// from the standalone DNS proxy and updates the DNS rules and IP cache
// accordingly. It receives the DNS rules during the endpoint regeneration
// event and listens for ip cache updates from the ipcache.
var Cell = cell.Module(
	"sdp-grpc-server",
	"Provides the standalone DNS proxy gRPC server",

	cell.Config(defaultConfig),
	cell.Provide(newDefaultListener),
	cell.Provide(newServer),
)

type serverParams struct {
	cell.In

	Logger            *slog.Logger
	EndpointManager   endpointmanager.EndpointManager
	DNSRequestHandler messagehandler.DNSMessageHandler
	IPCache           *ipcache.IPCache
	JobGroup          job.Group
	Config            FQDNConfig
	DaemonConfig      *option.DaemonConfig
	DefaultListener   listenConfig
}

func newServer(params serverParams) *FQDNDataServer {
	srv := NewServer(params.EndpointManager, params.DNSRequestHandler, params.Config.StandaloneDNSProxyServerPort, params.Logger, params.DefaultListener)

	if !params.Config.EnableStandaloneDNSProxy {
		return srv
	}

	if !params.DaemonConfig.EnableL7Proxy {
		srv.log.Error("Standalone DNS proxy requires L7 proxy to be enabled")
		return srv
	}

	if params.DaemonConfig.ToFQDNsProxyPort == 0 || params.Config.StandaloneDNSProxyServerPort == 0 {
		srv.log.Error("Standalone DNS proxy requires a valid port number to be set")
		return srv
	}

	params.IPCache.AddListener(srv)

	params.JobGroup.Add(job.OneShot("sdp-grpc-server", srv.ListenAndServe,
		job.WithRetry(3, &job.ExponentialBackoff{Min: 1 * time.Second, Max: 5 * time.Second}),
		job.WithShutdown()))

	return srv
}

const (
	// EnableStandaloneDNSProxy is the name of the option to enable standalone DNS proxy
	EnableStandaloneDNSProxy = "enable-standalone-dns-proxy"

	// StandaloneDNSProxyServerPort is the port on which the standalone DNS proxy gRPC server should listen.
	StandaloneDNSProxyServerPort = "standalone-dns-proxy-server-port"
)

type FQDNConfig struct {
	// EnableStandaloneDNSProxy is the option to enable standalone DNS proxy
	EnableStandaloneDNSProxy bool

	// StandaloneDNSProxyServerPort is the user-configured global, Standalone DNS proxy gRPC server port
	StandaloneDNSProxyServerPort int
}

var defaultConfig = FQDNConfig{
	EnableStandaloneDNSProxy:     false,
	StandaloneDNSProxyServerPort: 40045,
}

func (def FQDNConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableStandaloneDNSProxy, def.EnableStandaloneDNSProxy, "Enables standalone DNS proxy")
	flags.Int(StandaloneDNSProxyServerPort, def.StandaloneDNSProxyServerPort, "Global port on which the gRPC server for standalone DNS proxy should listen")
}
