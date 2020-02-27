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

package main

import (
	"context"
	"fmt"
	"time"

	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	azureAPI "github.com/cilium/cilium/pkg/azure/api"
	azureIPAM "github.com/cilium/cilium/pkg/azure/ipam"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// startAzureAllocator starts the Azure IP allocator
func startAzureAllocator(clientQPSLimit float64, clientBurst int) error {
	var (
		azMetrics azureAPI.MetricsAPI
		iMetrics  ipam.MetricsAPI
	)

	log.Info("Starting Azure IP allocator...")

	if option.Config.AzureSubscriptionID == "" {
		return fmt.Errorf("Azure subscription ID not specified")
	}

	if option.Config.AzureResourceGroup == "" {
		return fmt.Errorf("Azure resource group not specified")
	}

	if option.Config.EnableMetrics {
		azMetrics = apiMetrics.NewPrometheusMetrics(metricNamespace, "azure", registry)
		iMetrics = ipamMetrics.NewPrometheusMetrics(metricNamespace, registry)
	} else {
		azMetrics = &apiMetrics.NoOpMetrics{}
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}

	azureClient, err := azureAPI.NewClient(option.Config.AzureSubscriptionID,
		option.Config.AzureResourceGroup, azMetrics, clientQPSLimit, clientBurst)
	if err != nil {
		return fmt.Errorf("unable to create Azure client: %s", err)
	}
	instances := azureIPAM.NewInstancesManager(azureClient)
	nodeManager, err = ipam.NewNodeManager(instances, &ciliumNodeUpdateImplementation{}, iMetrics, option.Config.ParallelAllocWorkers, false)
	if err != nil {
		return fmt.Errorf("unable to initialize Azure node manager: %s", err)
	}

	instances.Resync(context.TODO())

	// Start an interval based  background resync for safety, it will
	// synchronize the state regularly and resolve eventual deficit if the
	// event driven trigger fails, and also release excess IP addresses
	// if release-excess-ips is enabled
	go func() {
		time.Sleep(time.Minute)
		mngr := controller.NewManager()
		mngr.UpdateController("azure-api-refresh",
			controller.ControllerParams{
				RunInterval: time.Minute,
				DoFunc: func(ctx context.Context) error {
					syncTime := instances.Resync(ctx)
					nodeManager.Resync(ctx, syncTime)
					return nil
				},
			})
	}()

	return nil
}
