// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_azure

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/ipam/allocator/azure"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	allocators = append(allocators, cell.Module(
		"azure-ipam-allocator",
		"Azure IP Allocator",

		cell.Config(azureDefaultConfig),
		cell.Invoke(startAzureAllocator),
	))
}

type AzureConfig struct {
	AzureSubscriptionID         string
	AzureResourceGroup          string
	AzureUserAssignedIdentityID string
	AzureUsePrimaryAddress      bool
}

var azureDefaultConfig = AzureConfig{
	AzureSubscriptionID:         "",
	AzureResourceGroup:          "",
	AzureUserAssignedIdentityID: "",
	AzureUsePrimaryAddress:      false,
}

func (cfg AzureConfig) Flags(flags *pflag.FlagSet) {
	flags.String(operatorOption.AzureSubscriptionID, azureDefaultConfig.AzureSubscriptionID, "Subscription ID to access Azure API")
	flags.String(operatorOption.AzureResourceGroup, azureDefaultConfig.AzureResourceGroup, "Resource group to use for Azure IPAM")
	flags.String(operatorOption.AzureUserAssignedIdentityID, azureDefaultConfig.AzureUserAssignedIdentityID, "ID of the user assigned identity used to auth with the Azure API")
	flags.Bool(operatorOption.AzureUsePrimaryAddress, azureDefaultConfig.AzureUsePrimaryAddress, "Use Azure IP address from interface's primary IPConfigurations")
}

type azureParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	MetricsRegistry    *metrics.Registry
	DaemonCfg          *option.DaemonConfig
	NodeWatcherFactory nodeWatcherJobFactory

	Cfg      Config
	AzureCfg AzureConfig
}

func startAzureAllocator(p azureParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMAzure {
		return
	}

	allocator := &azure.AllocatorAzure{
		AzureSubscriptionID:         p.AzureCfg.AzureSubscriptionID,
		AzureResourceGroup:          p.AzureCfg.AzureResourceGroup,
		AzureUserAssignedIdentityID: p.AzureCfg.AzureUserAssignedIdentityID,
		AzureUsePrimaryAddress:      p.AzureCfg.AzureUsePrimaryAddress,
		ParallelAllocWorkers:        p.Cfg.ParallelAllocWorkers,
	}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := allocator.Init(ctx, p.Logger, p.MetricsRegistry); err != nil {
					return fmt.Errorf("unable to init AWS allocator: %w", err)
				}

				nm, err := allocator.Start(ctx, &ciliumNodeUpdateImplementation{p.Clientset}, p.MetricsRegistry)
				if err != nil {
					return fmt.Errorf("unable to start AWS allocator: %w", err)
				}

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}
