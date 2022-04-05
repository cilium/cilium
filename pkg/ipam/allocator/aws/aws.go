// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	ec2shim "github.com/cilium/cilium/pkg/aws/ec2"
	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/aws/eni/limits"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-aws")

// AllocatorAWS is an implementation of IPAM allocator interface for AWS ENI
type AllocatorAWS struct {
	client *ec2shim.Client
}

// Init sets up ENI limits based on given options
func (a *AllocatorAWS) Init(ctx context.Context) error {
	var aMetrics ec2shim.MetricsAPI

	cfg, err := ec2shim.NewConfig(ctx)
	if err != nil {
		return err
	}
	subnetsFilters := ec2shim.NewSubnetsFilters(operatorOption.Config.IPAMSubnetsTags, operatorOption.Config.IPAMSubnetsIDs)
	instancesFilters := ec2shim.NewInstancesFilters(operatorOption.Config.IPAMInstanceTags)

	if operatorOption.Config.EnableMetrics {
		aMetrics = apiMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, "ec2", operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
	}
	a.client = ec2shim.NewClient(ec2.NewFromConfig(cfg), aMetrics, operatorOption.Config.IPAMAPIQPSLimit, operatorOption.Config.IPAMAPIBurst, subnetsFilters, instancesFilters, operatorOption.Config.ENITags)

	if err := limits.UpdateFromUserDefinedMappings(operatorOption.Config.AWSInstanceLimitMapping); err != nil {
		return fmt.Errorf("failed to parse aws-instance-limit-mapping: %w", err)
	}
	if operatorOption.Config.UpdateEC2AdapterLimitViaAPI {
		if err := limits.UpdateFromEC2API(ctx, a.client); err != nil {
			return fmt.Errorf("unable to update instance type to adapter limits from EC2 API: %w", err)
		}
	}
	return nil
}

// Start kicks of ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (a *AllocatorAWS) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	var iMetrics ipam.MetricsAPI

	log.Info("Starting ENI allocator...")

	if operatorOption.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, operatorMetrics.Registry)
	} else {
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}
	instances := eni.NewInstancesManager(a.client)
	nodeManager, err := ipam.NewNodeManager(instances, getterUpdater, iMetrics,
		operatorOption.Config.ParallelAllocWorkers, operatorOption.Config.AWSReleaseExcessIPs,
		operatorOption.Config.AWSEnablePrefixDelegation)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ENI node manager: %w", err)
	}

	if err := nodeManager.Start(ctx); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
