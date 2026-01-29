// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package azure

import (
	"context"
	"fmt"
	"log/slog"

	operatorOption "github.com/cilium/cilium/operator/option"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	azureAPI "github.com/cilium/cilium/pkg/azure/api"
	azureIPAM "github.com/cilium/cilium/pkg/azure/ipam"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

// AllocatorAzure is an implementation of IPAM allocator interface for Azure
type AllocatorAzure struct {
	AzureSubscriptionID         string
	AzureResourceGroup          string
	AzureUserAssignedIdentityID string
	AzureUsePrimaryAddress      bool
	ParallelAllocWorkers        int64

	rootLogger *slog.Logger
	logger     *slog.Logger
}

// Init in Azure implementation doesn't need to do anything
func (a *AllocatorAzure) Init(ctx context.Context, logger *slog.Logger, reg *metrics.Registry) error {
	a.rootLogger = logger
	a.logger = a.rootLogger.With(logfields.LogSubsys, "ipam-allocator-azure")
	return nil
}

// Start kicks of the Azure IP allocation
func (a *AllocatorAzure) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater, reg *metrics.Registry) (allocator.NodeEventHandler, error) {

	var (
		azMetrics azureAPI.MetricsAPI
		iMetrics  ipam.MetricsAPI
	)

	a.logger.Info("Starting Azure IP allocator...")

	a.logger.Debug("Retrieving Azure cloud name via Azure IMS")
	azureCloudName, err := azureAPI.GetAzureCloudName(ctx, a.rootLogger)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve Azure cloud name: %w", err)
	}

	subscriptionID := a.AzureSubscriptionID
	if subscriptionID == "" {
		a.logger.Debug("SubscriptionID was not specified via CLI, retrieving it via Azure IMS")
		subID, err := azureAPI.GetSubscriptionID(ctx, a.rootLogger)
		if err != nil {
			return nil, fmt.Errorf("Azure subscription ID was not specified via CLI and retrieving it from the Azure IMS was not possible: %w", err)
		}
		subscriptionID = subID
		a.logger.Debug("Detected subscriptionID via Azure IMS", logfields.SubscriptionID, subscriptionID)
	}

	resourceGroupName := a.AzureResourceGroup
	if resourceGroupName == "" {
		a.logger.Debug("ResourceGroupName was not specified via CLI, retrieving it via Azure IMS")
		rgName, err := azureAPI.GetResourceGroupName(ctx, a.rootLogger)
		if err != nil {
			return nil, fmt.Errorf("Azure resource group name was not specified via CLI and retrieving it from the Azure IMS was not possible: %w", err)
		}
		resourceGroupName = rgName
		a.logger.Debug("Detected resource group name via Azure IMS", logfields.Resource, resourceGroupName)
	}

	if operatorOption.Config.EnableMetrics {
		azMetrics = apiMetrics.NewPrometheusMetrics(metrics.Namespace, "azure", reg)
		iMetrics = ipamMetrics.NewPrometheusMetrics(metrics.Namespace, reg)
	} else {
		azMetrics = &apiMetrics.NoOpMetrics{}
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}

	azureClient, err := azureAPI.NewClient(a.rootLogger, azureCloudName, subscriptionID, resourceGroupName, a.AzureUserAssignedIdentityID, azMetrics, operatorOption.Config.IPAMAPIQPSLimit, operatorOption.Config.IPAMAPIBurst, a.AzureUsePrimaryAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to create Azure client: %w", err)
	}
	instances := azureIPAM.NewInstancesManager(a.rootLogger, azureClient)
	nodeManager, err := ipam.NewNodeManager(a.logger, instances, getterUpdater, iMetrics, a.ParallelAllocWorkers, false, 0, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Azure node manager: %w", err)
	}

	if err := nodeManager.Start(ctx); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
