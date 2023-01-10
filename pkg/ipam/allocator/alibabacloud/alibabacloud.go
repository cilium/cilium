// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alibabacloud

import (
	"context"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"

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
		aMetrics = apiMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, "alibabacloud", operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
	}

	var err error
	vpcID := operatorOption.Config.AlibabaCloudVPCID
	if vpcID == "" {
		vpcID, err = metadata.GetVPCID(ctx)
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
	// Send API requests to "vpc" network endpoints instead of the default "public" network
	// endpoints, so the ECS instance hosting cilium-operator doesn't require public network access
	// to reach alibabacloud API.
	// vpc endpoints are spliced to the format: <product>-<network>.<region_id>.aliyuncs.com
	// e.g. ecs-vpc.cn-shanghai.aliyuncs.com
	// ref https://github.com/aliyun/alibaba-cloud-sdk-go/blob/master/docs/11-Endpoint-EN.md
	vpcClient.Network = "vpc"
	ecsClient.Network = "vpc"

	vpcClient.GetConfig().WithScheme("HTTPS")
	ecsClient.GetConfig().WithScheme("HTTPS")

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
func (a *AllocatorAlibabaCloud) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	var iMetrics ipam.MetricsAPI

	log.Info("Starting AlibabaCloud ENI allocator...")

	if operatorOption.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, operatorMetrics.Registry)
	} else {
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}
	instances := eni.NewInstancesManager(a.client)
	nodeManager, err := ipam.NewNodeManager(instances, getterUpdater, iMetrics,
		operatorOption.Config.ParallelAllocWorkers, operatorOption.Config.AlibabaCloudReleaseExcessIPs, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AlibabaCloud node manager: %w", err)
	}

	if err := nodeManager.Start(ctx); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
