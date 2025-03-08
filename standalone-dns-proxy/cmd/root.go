// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	DNSProxy = cell.Module(
		"standalone-dns-proxy",
		"Standalone DNS Proxy",

		cell.Provide(func() *option.DaemonConfig { return option.Config }),
		cell.Invoke(registerDNSProxyHooks),
	)

	binaryName = "standalone-dns-proxy"

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)
)

func NewDNSProxyCmd(h *hive.Hive) *cobra.Command {
	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cobraCmd *cobra.Command, args []string) {
			initEnv(h.Viper())

			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				log.Fatal(err)
			}
		},
	}
	h.RegisterFlags(cmd.Flags())

	InitGlobalFlags(cmd, h.Viper())
	cmd.AddCommand(
		h.Command(),
	)
	cobra.OnInitialize(option.InitConfig(cmd, "Standalone-DNS-Proxy", "standalone-dns-proxy", h.Viper()))

	return cmd
}

func initEnv(vp *viper.Viper) {
	option.Config.Populate(vp)
	option.LogRegisteredOptions(vp, log)
}

func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func registerDNSProxyHooks(lc cell.Lifecycle) {
	args := &StandaloneDNSProxyArgs{
		DNSProxyConfig: dnsproxy.DNSProxyConfig{
			Address:                "",
			Port:                   uint16(option.Config.ToFQDNsProxyPort),
			IPv4:                   option.Config.EnableIPv4,
			IPv6:                   option.Config.EnableIPv6,
			EnableDNSCompression:   option.Config.ToFQDNsEnableDNSCompression,
			MaxRestoreDNSIPs:       option.Config.DNSMaxIPsPerRestoredRule,
			ConcurrencyLimit:       option.Config.DNSProxyConcurrencyLimit,
			ConcurrencyGracePeriod: option.Config.DNSProxyConcurrencyProcessingGracePeriod,
			DNSProxyType:           dnsproxy.StandaloneDNSProxy,
		},
		toFqdnServerPort:         uint16(option.Config.ToFqdnsServerPort),
		enableL7Proxy:            option.Config.EnableL7Proxy,
		enableStandaloneDNsProxy: option.Config.EnableStandaloneDNSProxy,
	}

	sdp, err := NewStandaloneDNSProxy(args)
	if err != nil {
		log.WithError(err).Fatal("Failed to create Standalone DNS Proxy")
	}

	// Todo: add the log with individual fields
	log.WithField("Standalone Args", args).Info("Starting Standalone DNS Proxy")

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return sdp.StartStandaloneDNSProxy()
		},
		OnStop: func(cell.HookContext) error {
			return sdp.StopStandaloneDNSProxy()
		},
	})
}
