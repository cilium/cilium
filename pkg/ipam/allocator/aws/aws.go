// Copyright 2019-2020 Authors of Cilium
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

package aws

import (
	"context"
	"fmt"

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

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-aws")

// AllocatorAWS is an implementation of IPAM allocator interface for AWS ENI
type AllocatorAWS struct {
	client *ec2shim.Client
}

// Init sets up ENI limits based on given options
func (a *AllocatorAWS) Init() error {
	var aMetrics ec2shim.MetricsAPI

	cfg, err := ec2shim.NewConfig()
	if err != nil {
		return err
	}
	subnetsFilters := ec2shim.NewSubnetsFilters(operatorOption.Config.IPAMSubnetsTags, operatorOption.Config.IPAMSubnetsIDs)

	if operatorOption.Config.EnableMetrics {
		aMetrics = apiMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, "ec2", operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
	}
	a.client = ec2shim.NewClient(ec2.New(cfg), aMetrics, operatorOption.Config.IPAMAPIQPSLimit, operatorOption.Config.IPAMAPIBurst, subnetsFilters)

	if err := limits.UpdateFromUserDefinedMappings(operatorOption.Config.AWSInstanceLimitMapping); err != nil {
		return fmt.Errorf("failed to parse aws-instance-limit-mapping: %w", err)
	}
	if operatorOption.Config.UpdateEC2AdapterLimitViaAPI {
		if err := limits.UpdateFromEC2API(context.TODO(), a.client); err != nil {
			return fmt.Errorf("unable to update instance type to adapter limits from EC2 API: %w", err)
		}
	}
	return nil
}

// Start kicks of ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (a *AllocatorAWS) Start(getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	var iMetrics ipam.MetricsAPI

	log.Info("Starting ENI allocator...")

	if operatorOption.Config.EnableMetrics {
		iMetrics = ipamMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, operatorMetrics.Registry)
	} else {
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}
	instances := eni.NewInstancesManager(a.client, operatorOption.Config.ENITags)
	nodeManager, err := ipam.NewNodeManager(instances, getterUpdater, iMetrics,
		operatorOption.Config.ParallelAllocWorkers, operatorOption.Config.AWSReleaseExcessIPs)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ENI node manager: %w", err)
	}

	if err := nodeManager.Start(context.TODO()); err != nil {
		return nil, err
	}

	return nodeManager, nil
}
