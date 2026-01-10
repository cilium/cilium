// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/accesslog/endpoint"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the L7 Proxy which provides support for L7 network policies.
// It is manages the different L7 proxies (Envoy, CoreDNS, ...) and the
// traffic redirection to them.
var Cell = cell.Module(
	"l7-proxy",
	"L7 Proxy provides support for L7 network policies",

	cell.Provide(newProxy),
	cell.Provide(newEnvoyProxyIntegration),
	cell.Config(defaultEnvoyProxyIntegrationConfig),
	cell.Provide(newDNSProxyIntegration),
	cell.ProvidePrivate(endpoint.NewEndpointInfoRegistry),
	cell.Provide(proxyports.NewProxyPorts),
	cell.Config(proxyports.ProxyPortsConfig{}),
	accesslog.Cell,
)

type proxyParams struct {
	cell.In

	Lifecycle             cell.Lifecycle
	JobGroup              job.Group
	Logger                *slog.Logger
	DaemonConfig          *option.DaemonConfig
	LocalNodeStore        *node.LocalNodeStore
	ProxyPorts            *proxyports.ProxyPorts
	EnvoyProxyIntegration *envoyProxyIntegration
	DNSProxyIntegration   *dnsProxyIntegration

	DB           *statedb.DB
	Devices      statedb.Table[*tables.Device]
	RouteManager *reconciler.DesiredRouteManager
}

type EnvoyProxyIntegrationConfig struct {
	ProxyUseOriginalSourceAddress bool
}

var defaultEnvoyProxyIntegrationConfig = EnvoyProxyIntegrationConfig{
	ProxyUseOriginalSourceAddress: true,
}

func (def EnvoyProxyIntegrationConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("proxy-use-original-source-address", def.ProxyUseOriginalSourceAddress, "Controls if Cilium's Envoy BPF metadata listener filter for L7 policy enforcement redirects should be configured to use original source address when extracting the metadata (doesn't affect Ingress/Gateway API).")
}

func newProxy(params proxyParams) (*Proxy, error) {
	p, err := createProxy(option.Config.EnableL7Proxy, params.Logger, params.LocalNodeStore, params.ProxyPorts, params.EnvoyProxyIntegration, params.DNSProxyIntegration, params.DB, params.Devices, params.RouteManager)
	if err != nil {
		return nil, fmt.Errorf("unable to create proxy: %w", err)
	}

	if !option.Config.EnableL7Proxy {
		params.Logger.Info("L7 proxies are disabled")
		if option.Config.EnableEnvoyConfig {
			params.Logger.Warn("CiliumEnvoyConfig functionality isn't enabled when L7 proxies are disabled", logfields.Flag, option.EnableEnvoyConfig)
		}

		return p, nil
	}

	if !params.DaemonConfig.DryMode {
		params.Lifecycle.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				if err := linuxdatapath.NodeEnsureLocalRoutingRule(); err != nil {
					return fmt.Errorf("failed to ensure local routing rule: %w", err)
				}
				return nil
			},
		})
	}

	p.proxyPorts.Trigger = job.NewTrigger(job.WithDebounce(10 * time.Second))

	params.JobGroup.Add(job.OneShot("proxy-ports-restore", func(ctx context.Context, health cell.Health) error {
		if err := p.proxyPorts.RestoreProxyPorts(ctx, health); err != nil {
			// report error to health but proceed to start the checkpoint job
			health.Degraded("restore from file failed", err)
		}

		// Restore all proxy ports before we register the job to overwrite the file below
		params.JobGroup.Add(job.Timer("proxy-ports-checkpoint",
			p.proxyPorts.StoreProxyPorts,
			time.Minute, /* periodic save in case of I/O errors */
			job.WithTrigger(p.proxyPorts.Trigger),
		))

		return nil
	}))

	// Register final save at shutdown
	params.Lifecycle.Append(cell.Hook{
		OnStop: func(ctx cell.HookContext) error {
			// ignore errors at shutdown
			_ = p.proxyPorts.StoreProxyPorts(ctx)
			return nil
		},
	})

	return p, nil
}

type envoyProxyIntegrationParams struct {
	cell.In

	IptablesManager datapath.IptablesManager
	XdsServer       envoy.XDSServer
	AdminClient     *envoy.EnvoyAdminClient
	Cfg             EnvoyProxyIntegrationConfig
}

func newEnvoyProxyIntegration(params envoyProxyIntegrationParams) *envoyProxyIntegration {
	return &envoyProxyIntegration{
		xdsServer:                     params.XdsServer,
		iptablesManager:               params.IptablesManager,
		adminClient:                   params.AdminClient,
		proxyUseOriginalSourceAddress: params.Cfg.ProxyUseOriginalSourceAddress,
	}
}

func newDNSProxyIntegration(dnsProxy fqdnproxy.DNSProxier, sdpPolicyUpdater *service.FQDNDataServer) *dnsProxyIntegration {
	return &dnsProxyIntegration{
		dnsProxy:         dnsProxy,
		sdpPolicyUpdater: sdpPolicyUpdater,
	}
}
