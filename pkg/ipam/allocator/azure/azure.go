// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azure

import (
	"context"
	"fmt"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	azureAPI "github.com/cilium/cilium/pkg/azure/api"
	azureIPAM "github.com/cilium/cilium/pkg/azure/ipam"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-azure")

// AllocatorAzure is an implementation of IPAM allocator interface for Azure
type AllocatorAzure struct{}

// Init in Azure implementation doesn't need to do anything
func (*AllocatorAzure) Init(ctx context.Context) error { return nil }

// Start kicks of the Azure IP allocation
func (*AllocatorAzure) Start(getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {

	var (
		azMetrics azureAPI.MetricsAPI
		iMetrics  ipam.MetricsAPI
	)

	log.Info("Starting Azure IP allocator...")

	subscriptionID := operatorOption.Config.AzureSubscriptionID
	if subscriptionID == "" {
		log.Debug("SubscriptionID was not specified via CLI, retrieving it via Azure IMS")
		subID, err := azureAPI.GetSubscriptionID(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("Azure subscription ID was not specified via CLI and retrieving it from the Azure IMS was not possible: %w", err)
		}
		subscriptionID = subID
		log.WithField("subscriptionID", subscriptionID).Debug("Detected subscriptionID via Azure IMS")
	}

	resourceGroupName := operatorOption.Config.AzureResourceGroup
	if resourceGroupName == "" {
		log.Debug("ResourceGroupName was not specified via CLI, retrieving it via Azure IMS")
		rgName, err := azureAPI.GetResourceGroupName(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("Azure resource group name was not specified via CLI and retrieving it from the Azure IMS was not possible: %w", err)
		}
		resourceGroupName = rgName
		log.WithField("resourceGroupName", resourceGroupName).Debug("Detected resource group name via Azure IMS")
	}

	if operatorOption.Config.EnableMetrics {
		azMetrics = apiMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, "azure", operatorMetrics.Registry)
		iMetrics = ipamMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, operatorMetrics.Registry)
	} else {
		azMetrics = &apiMetrics.NoOpMetrics{}
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}

	azureClient, err := azureAPI.NewClient(operatorOption.Config.AzureCloudName, subscriptionID, resourceGroupName, operatorOption.Config.AzureUserAssignedIdentityID, azMetrics, operatorOption.Config.IPAMAPIQPSLimit, operatorOption.Config.IPAMAPIBurst, operatorOption.Config.AzureUsePrimaryAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to create Azure client: %w", err)
	}
	instances := azureIPAM.NewInstancesManager(azureClient)
	nodeManager, err := ipam.NewNodeManager(instances, getterUpdater, iMetrics, operatorOption.Config.ParallelAllocWorkers, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Azure node manager: %w", err)
	}

	if err := nodeManager.Start(context.TODO()); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
