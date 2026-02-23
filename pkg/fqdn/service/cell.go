// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
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

	cell.Config(DefaultConfig),
	cell.Provide(newDefaultListener),
	cell.ProvidePrivate(newPolicyRulesTable),
	cell.ProvidePrivate(newIdentityToIPsTable),
	cell.Provide(newServer),
)

type serverParams struct {
	cell.In

	Logger             *slog.Logger
	EndpointsLookup    endpointmanager.EndpointsLookup
	DNSRequestHandler  messagehandler.DNSMessageHandler
	IPCache            *ipcache.IPCache
	JobGroup           job.Group
	Config             FQDNConfig
	DaemonConfig       *option.DaemonConfig
	DefaultListener    listenConfig
	DB                 *statedb.DB
	PolicyRulesTable   statedb.RWTable[PolicyRules]
	IdentityToIPsTable statedb.RWTable[identityToIPs]
}

func newServer(params serverParams) *FQDNDataServer {

	if !params.Config.EnableStandaloneDNSProxy {
		return nil
	}

	if !params.DaemonConfig.EnableL7Proxy {
		params.Logger.Error("Standalone DNS proxy requires L7 proxy to be enabled")
		return nil
	}

	if params.DaemonConfig.ToFQDNsProxyPort == 0 || params.Config.StandaloneDNSProxyServerPort == 0 {
		params.Logger.Error("Standalone DNS proxy requires a valid port number to be set")
		return nil
	}

	srv := NewServer(params)
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

	// DNSMaxIPsPerRestoredRule defines the maximum number of IPs to maintain
	// for each FQDN selector in endpoint's restored DNS rules
	DNSMaxIPsPerRestoredRule = "dns-max-ips-per-restored-rule"

	// ToFQDNsEnableDNSCompression allows the DNS proxy to compress responses to
	// endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
	ToFQDNsEnableDNSCompression = "tofqdns-enable-dns-compression"

	// DNSProxyConcurrencyProcessingGracePeriod is the amount of grace time to
	// wait while processing DNS messages when the DNSProxyConcurrencyLimit has
	// been reached.
	DNSProxyConcurrencyProcessingGracePeriod = "dnsproxy-concurrency-processing-grace-period"
)

type FQDNConfig struct {
	// EnableStandaloneDNSProxy is the option to enable standalone DNS proxy
	EnableStandaloneDNSProxy bool

	// StandaloneDNSProxyServerPort is the user-configured global, Standalone DNS proxy gRPC server port
	StandaloneDNSProxyServerPort int

	// ToFQDNsEnableDNSCompression allows the DNS proxy to compress responses to
	// endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
	ToFQDNsEnableDNSCompression bool

	// DNSMaxIPsPerRestoredRule defines the maximum number of IPs to maintain
	// for each FQDN selector in endpoint's restored DNS rules
	DNSMaxIPsPerRestoredRule int

	// DNSProxyConcurrencyProcessingGracePeriod is the amount of grace time to
	// wait while processing DNS messages when the DNSProxyConcurrencyLimit has
	// been reached.
	DNSProxyConcurrencyProcessingGracePeriod time.Duration
}

var DefaultConfig = FQDNConfig{
	EnableStandaloneDNSProxy:                 false,
	StandaloneDNSProxyServerPort:             10095,
	ToFQDNsEnableDNSCompression:              true,
	DNSMaxIPsPerRestoredRule:                 1000,
	DNSProxyConcurrencyProcessingGracePeriod: 0,
}

func (def FQDNConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableStandaloneDNSProxy, def.EnableStandaloneDNSProxy, "Enables standalone DNS proxy")
	flags.Int(StandaloneDNSProxyServerPort, def.StandaloneDNSProxyServerPort, "Global port on which the gRPC server for standalone DNS proxy should listen")
	flags.Bool(ToFQDNsEnableDNSCompression, def.ToFQDNsEnableDNSCompression, "Allow the DNS proxy to compress responses to endpoints that are larger than 512 Bytes or the EDNS0 option, if present")
	flags.Int(DNSMaxIPsPerRestoredRule, def.DNSMaxIPsPerRestoredRule, "Maximum number of IPs to maintain for each restored DNS rule")
	flags.Duration(DNSProxyConcurrencyProcessingGracePeriod, def.DNSProxyConcurrencyProcessingGracePeriod, "Grace time to wait when DNS proxy concurrent limit has been reached during DNS message processing")
}
