// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	ec2shim "github.com/cilium/cilium/pkg/aws/ec2"
	"github.com/cilium/cilium/pkg/aws/eni"
	"github.com/cilium/cilium/pkg/aws/eni/limits"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-aws")

// AllocatorAWS is an implementation of IPAM allocator interface for AWS ENI
type AllocatorAWS struct {
	client    *ec2shim.Client
	eniGCTags map[string]string
}

func initENIGarbageCollectionTags(ctx context.Context, cfg aws.Config) (eniTags map[string]string) {
	// Use user-provided tags if available
	if len(operatorOption.Config.ENIGarbageCollectionTags) != 0 {
		return operatorOption.Config.ENIGarbageCollectionTags
	}

	eniTags = map[string]string{
		defaults.ENIGarbageCollectionTagManagedName: defaults.ENIGarbageCollectionTagManagedValue,
		defaults.ENIGarbageCollectionTagClusterName: defaults.ENIGarbageCollectionTagClusterValue,
	}

	// Use cilium cluster name if available
	if clusterName := option.Config.ClusterName; clusterName != defaults.ClusterName {
		eniTags[defaults.ENIGarbageCollectionTagClusterName] = clusterName
		return eniTags
	}

	// Try to auto-detect EKS cluster name
	clusterName, err := ec2shim.DetectEKSClusterName(ctx, cfg)
	if err != nil {
		log.WithError(err).Debug("Auto-detection of EKS cluster name failed")
	} else {
		log.WithField(logfields.ClusterName, clusterName).
			Info("Auto-detected EKS cluster name for ENI garbage collection")
		eniTags[defaults.ENIGarbageCollectionTagClusterName] = clusterName
		return eniTags
	}

	log.Info("Unable to detect EKS cluster name for ENI garbage collection. " +
		"This operator instance may clean up dangling ENIs from other Cilium clusters. " +
		"Set a --cluster-name or cluster-specific --eni-gc-tags to prevent this.")
	return eniTags
}

// Init sets up ENI limits based on given options
func (a *AllocatorAWS) Init(ctx context.Context) error {
	var aMetrics ec2shim.MetricsAPI

	cfg, err := ec2shim.NewConfig(ctx)
	if err != nil {
		return err
	}
	subnetsFilters := ec2shim.NewSubnetsFilters(operatorOption.Config.IPAMSubnetsTags, operatorOption.Config.IPAMSubnetsIDs)
	instancesFilters := ec2shim.NewTagsFilter(operatorOption.Config.IPAMInstanceTags)

	if operatorOption.Config.EnableMetrics {
		aMetrics = apiMetrics.NewPrometheusMetrics(operatorMetrics.Namespace, "ec2", operatorMetrics.Registry)
	} else {
		aMetrics = &apiMetrics.NoOpMetrics{}
	}

	eniCreationTags := operatorOption.Config.ENITags
	if operatorOption.Config.ENIGarbageCollectionInterval > 0 {
		a.eniGCTags = initENIGarbageCollectionTags(ctx, cfg)
		// Make sure GC tags are also used for ENI creation
		eniCreationTags = ec2shim.MergeTags(eniCreationTags, a.eniGCTags)
	}

	a.client = ec2shim.NewClient(ec2.NewFromConfig(cfg), aMetrics, operatorOption.Config.IPAMAPIQPSLimit,
		operatorOption.Config.IPAMAPIBurst, subnetsFilters, instancesFilters, eniCreationTags,
		operatorOption.Config.AWSUsePrimaryAddress)

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

	if operatorOption.Config.ENIGarbageCollectionInterval > 0 {
		eni.StartENIGarbageCollector(ctx, a.client, eni.GarbageCollectionParams{
			RunInterval:    operatorOption.Config.ENIGarbageCollectionInterval,
			MaxPerInterval: defaults.ENIGarbageCollectionMaxPerInterval,
			ENITags:        a.eniGCTags,
		})
	}

	return nodeManager, nil
}
