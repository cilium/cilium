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
	"reflect"
	"time"

	azureAPI "github.com/cilium/cilium/pkg/azure/api"
	azureIPAM "github.com/cilium/cilium/pkg/azure/ipam"
	azureMetrics "github.com/cilium/cilium/pkg/azure/ipam/metrics"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// startAzureAllocator kicks of Azure allocation
func startAzureAllocator(awsClientQPSLimit float64, awsClientBurst int) error {
	log.Info("Starting Azure allocator...")

	subscriptionID := viper.GetString("azure-subscription-id")
	if subscriptionID == "" {
		return fmt.Errorf("Azure subscription ID not specified")
	}

	if enableMetrics {
		azureMetrics := metrics.NewPrometheusMetrics(metricNamespace, registry)
		azureClient := azureAPI.NewClient(subscriptionID, azureMetrics, awsClientQPSLimit, awsClientBurst)
		instances = azureIPAM.NewInstancesManager(azureClient)
		ipamMetrics := ipamMetrics.NewPrometheusMetrics(metricNamespace, registry)
		nodeManager, err = ipam.NewNodeManager(instances, &k8sAPI{}, ipamMetrics, eniParallelWorkers,
			option.Config.AwsReleaseExcessIps)
		if err != nil {
			return fmt.Errorf("unable to initialize Azure node manager: %s", err)
		}
	} else {
		// Inject dummy metrics operations that do nothing so we don't panic if
		// metrics aren't enabled
		azureClient := azureAPI.NewClient()
		instances = azureIPAM.NewInstancesManager(azureClient)
		nodeManager, err = ipam.NewNodeManager(instances, &k8sAPI{}, &noOpAzureMetrics{}, eniParallelWorkers,
			option.Config.AwsReleaseExcessIps)
		if err != nil {
			return fmt.Errorf("unable to initialize Azure node managerr: %s", err)
		}
	}

	instances.Resync(context.TODO())

	// Start an interval based  background resync for safety, it will
	// synchronize the state regularly and resolve eventual deficit if the
	// event driven trigger fails, and also release excess IP addresses
	// if release-excess-ips is enabled
	go func() {
		time.Sleep(time.Minute)
		mngr := controller.NewManager()
		mngr.UpdateController("azure-refresh",
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

type noOpAzureMetrics struct{}

func (m *noOpAzureMetrics) ObserveAzureAPICall(call, status string, duration float64)      {}
func (m *noOpAzureMetrics) ObserveAzureRateLimit(operation string, duration time.Duration) {}
