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

package main

import (
	"context"
	"fmt"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	ec2shim "github.com/cilium/cilium/pkg/aws/ec2"
	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/option"

	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/sirupsen/logrus"
)

// startENIAllocator kicks of ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func startENIAllocator(awsClientQPSLimit float64, awsClientBurst int, eniTags map[string]string) (*ipam.NodeManager, error) {
	var (
		aMetrics ec2shim.MetricsAPI
		iMetrics ipam.MetricsAPI
	)

	log.Info("Starting ENI allocator...")

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS configuration: %s", err)
	}

	log.Info("Retrieving own metadata from EC2 metadata server...")
	metadataClient := ec2metadata.New(cfg)
	instance, err := metadataClient.GetInstanceIdentityDocument()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve instance identity document: %s", err)
	}

	log.WithFields(logrus.Fields{
		"instance": instance.InstanceID,
		"region":   instance.Region,
	}).Info("Connected to EC2 metadata server")

	cfg.Region = instance.Region

	if option.Config.EnableMetrics {
		aMetrics = apiMetrics.NewPrometheusMetrics("ipam", operatorMetrics.Namespace, operatorMetrics.Registry)
		iMetrics = ipamMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}

	ec2Client := ec2shim.NewClient(ec2.New(cfg), aMetrics, awsClientQPSLimit, awsClientBurst)
	log.Info("Connected to EC2 service API")
	instances := eni.NewInstancesManager(ec2Client, eniTags)
	nodeManager, err := ipam.NewNodeManager(instances, &ciliumNodeUpdateImplementation{}, iMetrics,
		option.Config.ParallelAllocWorkers, option.Config.AwsReleaseExcessIps)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ENI node manager: %s", err)
	}

	nodeManager.Start(context.TODO())

	return nodeManager, nil
}
