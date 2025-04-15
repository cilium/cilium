// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alibabacloud

import (
	"context"
	"fmt"
	"log/slog"

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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

// Maximum number of tags for exact search of ECS resources.
// https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-listtagresources
const MaxInstanceTags = 20

var subsysLogAttr = []any{logfields.LogSubsys, "ipam-allocator-alibaba-cloud"}

// AllocatorAlibabaCloud is an implementation of IPAM allocator interface for AlibabaCloud ENI
type AllocatorAlibabaCloud struct {
	rootLogger *slog.Logger
	logger     *slog.Logger
	client     *openapi.Client
}

// Init sets up ENI limits based on given options
// Credential ref https://github.com/aliyun/alibaba-cloud-sdk-go/blob/master/docs/2-Client-EN.md
func (a *AllocatorAlibabaCloud) Init(ctx context.Context, logger *slog.Logger) error {
	a.rootLogger = logger
	a.logger = logger.With(subsysLogAttr...)
	var aMetrics openapi.MetricsAPI

	if operatorOption.Config.EnableMetrics {
		aMetrics = apiMetrics.NewPrometheusMetrics(metrics.Namespace, "alibabacloud", operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
	}

	if len(operatorOption.Config.IPAMInstanceTags) > MaxInstanceTags {
		return fmt.Errorf("number of tags in instance-tags-filter exceeds the limit %d", MaxInstanceTags)
	}

	var err error
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
		operatorOption.Config.IPAMAPIBurst, operatorOption.Config.IPAMInstanceTags)

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

	a.logger.Info("Starting AlibabaCloud ENI allocator...")

	if operatorOption.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewPrometheusMetrics(metrics.Namespace, operatorMetrics.Registry)
	} else {
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}
	instances := eni.NewInstancesManager(a.rootLogger, a.client)
	nodeManager, err := ipam.NewNodeManager(a.logger, instances, getterUpdater, iMetrics,
		operatorOption.Config.ParallelAllocWorkers, operatorOption.Config.AlibabaCloudReleaseExcessIPs, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AlibabaCloud node manager: %w", err)
	}

	if err := nodeManager.Start(ctx); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
