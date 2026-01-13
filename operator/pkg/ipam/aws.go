// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package ipam

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/ipam/allocator/aws"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func init() {
	allocators = append(allocators, cell.Module(
		"aws-ipam-allocator",
		"AWS IP Allocator",

		cell.Config(awsDefaultConfig),
		cell.Invoke(startAWSAllocator),
	))
}

type AWSConfig struct {
	AWSReleaseExcessIPs          bool
	ExcessIPReleaseDelay         int
	AWSEnablePrefixDelegation    bool
	ENITags                      map[string]string
	ENIGarbageCollectionTags     map[string]string `mapstructure:"eni-gc-tags"`
	ENIGarbageCollectionInterval time.Duration     `mapstructure:"eni-gc-interval"`
	AWSUsePrimaryAddress         bool
	EC2APIEndpoint               string
	AWSMaxResultsPerCall         int32
}

var awsDefaultConfig = AWSConfig{
	AWSReleaseExcessIPs:          false,
	ExcessIPReleaseDelay:         180,
	AWSEnablePrefixDelegation:    false,
	ENITags:                      nil,
	ENIGarbageCollectionTags:     nil,
	ENIGarbageCollectionInterval: 5 * time.Minute,
	AWSUsePrimaryAddress:         false,
	EC2APIEndpoint:               "",
	AWSMaxResultsPerCall:         0,
}

func (cfg AWSConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(operatorOption.AWSReleaseExcessIPs, awsDefaultConfig.AWSReleaseExcessIPs, "Enable releasing excess free IP addresses from AWS ENI.")
	flags.Int(operatorOption.ExcessIPReleaseDelay, awsDefaultConfig.ExcessIPReleaseDelay, "Number of seconds operator would wait before it releases an IP previously marked as excess")
	flags.Bool(operatorOption.AWSEnablePrefixDelegation, awsDefaultConfig.AWSEnablePrefixDelegation, "Allows operator to allocate prefixes to ENIs instead of individual IP addresses")
	flags.StringToString(operatorOption.ENITags, awsDefaultConfig.ENITags,
		"ENI tags in the form of k1=v1 (multiple k/v pairs can be passed by repeating the CLI flag)")
	flags.StringToString(operatorOption.ENIGarbageCollectionTags, awsDefaultConfig.ENIGarbageCollectionTags,
		"Additional tags attached to ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected")
	flags.Duration(operatorOption.ENIGarbageCollectionInterval, awsDefaultConfig.ENIGarbageCollectionInterval,
		"Interval for garbage collection of unattached ENIs. Set to 0 to disable")
	flags.Bool(operatorOption.AWSUsePrimaryAddress, awsDefaultConfig.AWSUsePrimaryAddress, "Allows for using primary address of the ENI for allocations on the node")
	flags.String(operatorOption.EC2APIEndpoint, awsDefaultConfig.EC2APIEndpoint, "AWS API endpoint for the EC2 service")
	flags.Int32(operatorOption.AWSMaxResultsPerCall, awsDefaultConfig.AWSMaxResultsPerCall, "Maximum results per AWS API call for DescribeNetworkInterfaces and DescribeSecurityGroups. Set to 0 to let AWS determine optimal page size (default). If set to 0 and AWS returns OperationNotPermitted errors, automatically switches to 1000 for all future requests")
}

type awsParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	MetricsRegistry    *metrics.Registry
	DaemonCfg          *option.DaemonConfig
	NodeWatcherFactory nodeWatcherJobFactory

	Cfg    Config
	AwsCfg AWSConfig
}

func startAWSAllocator(p awsParams) {
	if p.DaemonCfg.IPAM != ipamOption.IPAMENI {
		return
	}

	allocator := &aws.AllocatorAWS{
		AWSReleaseExcessIPs:          p.AwsCfg.AWSReleaseExcessIPs,
		ExcessIPReleaseDelay:         p.AwsCfg.ExcessIPReleaseDelay,
		AWSEnablePrefixDelegation:    p.AwsCfg.AWSEnablePrefixDelegation,
		ENITags:                      p.AwsCfg.ENITags,
		ENIGarbageCollectionTags:     p.AwsCfg.ENIGarbageCollectionTags,
		ENIGarbageCollectionInterval: p.AwsCfg.ENIGarbageCollectionInterval,
		AWSUsePrimaryAddress:         p.AwsCfg.AWSUsePrimaryAddress,
		EC2APIEndpoint:               p.AwsCfg.EC2APIEndpoint,
		AWSMaxResultsPerCall:         p.AwsCfg.AWSMaxResultsPerCall,
		ParallelAllocWorkers:         p.Cfg.ParallelAllocWorkers,
	}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := allocator.Init(ctx, p.Logger, p.MetricsRegistry); err != nil {
					return fmt.Errorf("unable to init AWS allocator: %w", err)
				}

				nm, err := allocator.Start(ctx, &ciliumNodeUpdateImplementation{p.Clientset}, p.MetricsRegistry)
				if err != nil {
					return fmt.Errorf("unable to start AWS allocator: %w", err)
				}

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}
