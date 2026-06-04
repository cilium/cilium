// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aws

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/ipam/allocator"
	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/pkg/aws/api"
	"github.com/cilium/cilium/pkg/aws/ipam"
	"github.com/cilium/cilium/pkg/aws/metadata"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var subsysLogAttr = []any{logfields.LogSubsys, "ipam-allocator-aws"}

// AllocatorAWS is an implementation of IPAM allocator interface for AWS ENI
type AllocatorAWS struct {
	AWSReleaseExcessIPs          bool
	ExcessIPReleaseDelay         int
	AWSEnablePrefixDelegation    bool
	ENITags                      map[string]string
	ENIGarbageCollectionTags     map[string]string
	ENIGarbageCollectionInterval time.Duration
	AWSUsePrimaryAddress         bool
	EC2APIEndpoint               string
	AWSMaxResultsPerCall         int32
	SubnetsIDs                   []string
	SubnetsTags                  map[string]string
	ParallelAllocWorkers         int64
	LimitIPAMAPIBurst            int
	LimitIPAMAPIQPS              float64
	AWSMetrics                   api.MetricsAPI

	rootLogger *slog.Logger
	logger     *slog.Logger
	client     *api.Client
	eniGCTags  map[string]string
}

func (a *AllocatorAWS) initENIGarbageCollectionTags(ctx context.Context, cfg aws.Config) (eniTags map[string]string) {
	// Use user-provided tags if available
	if len(a.ENIGarbageCollectionTags) != 0 {
		return a.ENIGarbageCollectionTags
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
	clusterName, err := api.DetectEKSClusterName(ctx, cfg)
	if err != nil {
		a.logger.Debug("Auto-detection of EKS cluster name failed", logfields.Error, err)
	} else {
		a.logger.Info(
			"Auto-detected EKS cluster name for ENI garbage collection",
			logfields.ClusterName, clusterName,
		)
		eniTags[defaults.ENIGarbageCollectionTagClusterName] = clusterName
		return eniTags
	}

	a.logger.Info("Unable to detect EKS cluster name for ENI garbage collection. " +
		"This operator instance may clean up dangling ENIs from other Cilium clusters. " +
		"Set a --cluster-name or cluster-specific --eni-gc-tags to prevent this.")
	return eniTags
}

// Init sets up ENI limits based on given options
func (a *AllocatorAWS) Init(ctx context.Context, logger *slog.Logger) error {
	a.rootLogger = logger
	a.logger = logger.With(subsysLogAttr...)

	cfg, err := api.NewConfig(ctx)
	if err != nil {
		return err
	}
	subnetsFilters := api.NewSubnetsFilters(a.SubnetsTags, a.SubnetsIDs)
	instancesFilters := api.NewTagsFilter(operatorOption.Config.IPAMInstanceTags)

	eniCreationTags := a.ENITags
	if a.ENIGarbageCollectionInterval > 0 {
		a.eniGCTags = a.initENIGarbageCollectionTags(ctx, cfg)
		// Make sure GC tags are also used for ENI creation
		eniCreationTags = api.MergeTags(eniCreationTags, a.eniGCTags)
	}

	optionsFunc := func(options *ec2.Options) {}
	if ec2APIEndpoint := a.EC2APIEndpoint; len(ec2APIEndpoint) > 0 {
		a.logger.Debug(
			"Using custom API endpoint for service",
			logfields.Endpoint, ec2APIEndpoint,
			logfields.Service, ec2.ServiceID,
		)
		optionsFunc = func(options *ec2.Options) {
			options.BaseEndpoint = aws.String("https://" + ec2APIEndpoint)
		}
	}

	a.client = api.NewClient(a.rootLogger, ec2.NewFromConfig(cfg, optionsFunc), a.AWSMetrics, a.LimitIPAMAPIQPS,
		a.LimitIPAMAPIBurst, subnetsFilters, instancesFilters, eniCreationTags,
		a.AWSUsePrimaryAddress, a.AWSMaxResultsPerCall)

	return nil
}

// Start kicks off ENI allocation, the initial connection to AWS
// APIs is done in a blocking manner, given that this is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (a *AllocatorAWS) Start(ctx context.Context, getterUpdater allocator.CiliumNodeGetterUpdater, iMetrics nodemanager.MetricsAPI) (allocator.NodeEventHandler, error) {
	a.logger.Info("Starting ENI allocator...")

	imds, err := metadata.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize metadata client: %w", err)
	}
	instances, err := ipam.NewInstancesManager(ctx, a.rootLogger, a.client, imds)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ENI instances manager: %w", err)
	}
	nodeManager, err := nodemanager.NewNodeManager(a.logger, instances, getterUpdater, iMetrics,
		a.ParallelAllocWorkers, a.AWSReleaseExcessIPs, a.ExcessIPReleaseDelay,
		a.AWSEnablePrefixDelegation)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize ENI node manager: %w", err)
	}

	if err := nodeManager.Start(ctx); err != nil {
		return nil, err
	}

	if a.ENIGarbageCollectionInterval > 0 {
		ipam.StartENIGarbageCollector(ctx, a.rootLogger, a.client, ipam.GarbageCollectionParams{
			RunInterval:    a.ENIGarbageCollectionInterval,
			MaxPerInterval: defaults.ENIGarbageCollectionMaxPerInterval,
			ENITags:        a.eniGCTags,
		})
	}

	return nodeManager, nil
}
