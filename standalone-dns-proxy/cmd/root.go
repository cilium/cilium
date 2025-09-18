// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/lookup"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/messagehandler"
)

var (
	// StandaloneDNSProxyCell provides the standalone DNS proxy functionality
	// It is responsible for starting and stopping the standalone DNS proxy
	// based on the configuration provided in the config. It connects to the
	// cilium agent via gRPC to receive DNS rules and send DNS responses.
	StandaloneDNSProxyCell = cell.Module(
		"standalone-dns-proxy",
		"Provides the standalone DNS proxy functionality",

		// includes the dns proxy
		bootstrap.Cell,

		// includes the gRPC client for communication with the cilium agent
		client.Cell,

		//includes the endpoint/identity lookup functionality needed by the DNS proxy
		lookup.Cell,

		// includes the message handler for receiving messages from the proxy and sending messages to the gRPC client which in turn sends them to the cilium agent
		messagehandler.Cell,

		cell.Provide(func() *option.DaemonConfig {
			return option.Config
		}),
		cell.Config(service.DefaultConfig),
		cell.Invoke(registerStandaloneDNSProxyHooks),
	)

	binaryName = "standalone-dns-proxy"
)

func NewDNSProxyCmd(h *hive.Hive) *cobra.Command {
	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cobraCmd *cobra.Command, args []string) {
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			initEnv(logging.DefaultSlogLogger, h.Viper())

			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				log.Fatal(err)
			}
		},
	}
	h.RegisterFlags(cmd.Flags())

	cmd.AddCommand(
		h.Command(),
	)

	// slogloggercheck: using default logger for configuration initialization
	cobra.OnInitialize(option.InitConfig(logging.DefaultSlogLogger, cmd, "Standalone-DNS-Proxy", "standalone-dns-proxy", h.Viper()))

	return cmd
}

func initEnv(logger *slog.Logger, vp *viper.Viper) {
	option.Config.Populate(logger, vp)
	option.LogRegisteredSlogOptions(vp, logger)
}

func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type standaloneDNSProxyParams struct {
	cell.In

	Logger            *slog.Logger
	AgentConfig       *option.DaemonConfig
	FQDNConfig        service.FQDNConfig
	Lifecycle         cell.Lifecycle
	JobGroup          job.Group
	ConnectionHandler client.ConnectionHandler
	DNSProxier        proxy.DNSProxier
	DNSRulesTable     statedb.RWTable[service.PolicyRules]
	DB                *statedb.DB
}

func registerStandaloneDNSProxyHooks(params standaloneDNSProxyParams) error {
	sdp := NewStandaloneDNSProxy(params)

	if params.AgentConfig.EnableL7Proxy && params.FQDNConfig.EnableStandaloneDNSProxy {
		sdp.logger.Info("Standalone DNS proxy is enabled")
	} else {
		return fmt.Errorf("standalone DNS proxy requires L7 proxy and standalone DNS proxy to be enabled in the configuration")
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return sdp.StartStandaloneDNSProxy()
		},
		OnStop: func(cell.HookContext) error {
			return sdp.StopStandaloneDNSProxy()
		},
	})
	return nil
}
