// Copyright 2021 Authors of Cilium
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

package alibabacloud

import (
	"context"
	"fmt"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	openapi "github.com/cilium/cilium/pkg/alibabacloud/api"
	"github.com/cilium/cilium/pkg/alibabacloud/eni"
	"github.com/cilium/cilium/pkg/alibabacloud/eni/limits"
	"github.com/cilium/cilium/pkg/alibabacloud/metadata"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-alibaba-cloud")

// AllocatorAlibabaCloud is an implementation of IPAM allocator interface for AlibabaCloud ENI
type AllocatorAlibabaCloud struct {
	client *openapi.Client
}

// Init sets up ENI limits based on given options
// Credential ref https://github.com/aliyun/alibaba-cloud-sdk-go/blob/master/docs/2-Client-EN.md
func (a *AllocatorAlibabaCloud) Init(ctx context.Context) error {
	var aMetrics openapi.MetricsAPI

	if operatorOption.Config.EnableMetrics {
		aMetrics = apiMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, "alibaba-cloud", operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
	}

	var err error
	vpcID := operatorOption.Config.AlibabaCloudVPCID
	if vpcID == "" {
		vpcID, err = metadata.GetVPCID(context.TODO())
		if err != nil {
			return err
		}
	}
	regionID, err := metadata.GetRegionID(ctx)
	if err != nil {
		return err
	}

	vpcClient, err := vpc.NewClientWithProvider(regionID)
	if err != nil {
		return err
	}
	ecsClient, err := ecs.NewClientWithProvider(regionID)
	if err != nil {
		return err
	}

	a.client = openapi.NewClient(vpcClient, ecsClient, aMetrics, operatorOption.Config.IPAMAPIQPSLimit,
		operatorOption.Config.IPAMAPIBurst, map[string]string{openapi.VPCID: vpcID})

	if err := limits.UpdateFromAPI(ctx, a.client); err != nil {
		return fmt.Errorf("unable to update instance type to adapter limits from AlibabaCloud API: %w", err)
	}

	return nil
}

// Start kicks off ENI allocation, the initial connection to AlibabaCloud
// APIs is done in a blocking manner. Provided this is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (a *AllocatorAlibabaCloud) Start(getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	var iMetrics ipam.MetricsAPI

	log.Info("Starting AlibabaCloud ENI allocator...")

	if operatorOption.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, operatorMetrics.Registry)
	} else {
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}
	instances := eni.NewInstancesManager(a.client)
	nodeManager, err := ipam.NewNodeManager(instances, getterUpdater, iMetrics,
		operatorOption.Config.ParallelAllocWorkers, operatorOption.Config.AlibabaCloudReleaseExcessIPs)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AlibabaCloud node manager: %w", err)
	}

	if err := nodeManager.Start(context.TODO()); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
