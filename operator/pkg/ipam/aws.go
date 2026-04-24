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

	"github.com/cilium/cilium/pkg/ipam/allocator/aws"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
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
		metrics.Metric(aws.NewMetrics),
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
	IPAMSubnetsIDs               []string          `mapstructure:"subnet-ids-filter"`
	IPAMSubnetsTags              map[string]string `mapstructure:"subnet-tags-filter"`
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
	IPAMSubnetsIDs:               nil,
	IPAMSubnetsTags:              nil,
}

func (cfg AWSConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("aws-release-excess-ips", awsDefaultConfig.AWSReleaseExcessIPs, "Enable releasing excess free IP addresses from AWS ENI.")
	flags.Int("excess-ip-release-delay", awsDefaultConfig.ExcessIPReleaseDelay, "Number of seconds operator would wait before it releases an IP previously marked as excess")
	flags.Bool("aws-enable-prefix-delegation", awsDefaultConfig.AWSEnablePrefixDelegation, "Allows operator to allocate prefixes to ENIs instead of individual IP addresses")
	flags.StringToString("eni-tags", awsDefaultConfig.ENITags,
		"ENI tags in the form of k1=v1 (multiple k/v pairs can be passed by repeating the CLI flag)")
	flags.StringToString("eni-gc-tags", awsDefaultConfig.ENIGarbageCollectionTags,
		"Additional tags attached to ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected")
	flags.Duration("eni-gc-interval", awsDefaultConfig.ENIGarbageCollectionInterval,
		"Interval for garbage collection of unattached ENIs. Set to 0 to disable")
	flags.Bool("aws-use-primary-address", awsDefaultConfig.AWSUsePrimaryAddress, "Allows for using primary address of the ENI for allocations on the node")
	flags.String("ec2-api-endpoint", awsDefaultConfig.EC2APIEndpoint, "AWS API endpoint for the EC2 service")
	flags.Int32("aws-max-results-per-call", awsDefaultConfig.AWSMaxResultsPerCall, "Maximum results per AWS API call for DescribeNetworkInterfaces and DescribeSecurityGroups. Set to 0 to let AWS determine optimal page size (default). If set to 0 and AWS returns OperationNotPermitted errors, automatically switches to 1000 for all future requests")
	flags.StringSlice("subnet-ids-filter", awsDefaultConfig.IPAMSubnetsIDs, "Subnets IDs (separated by commas)")
	flags.StringToString("subnet-tags-filter", awsDefaultConfig.IPAMSubnetsTags,
		"Subnets tags in the form of k1=v1,k2=v2 (multiple k/v pairs can also be passed by repeating the CLI flag")
}

type awsParams struct {
	cell.In

	Logger             *slog.Logger
	Lifecycle          cell.Lifecycle
	JobGroup           job.Group
	Clientset          k8sClient.Clientset
	EC2Metrics         *aws.Metrics
	IPAMMetrics        *ipamMetrics.Metrics
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
		SubnetsIDs:                   p.AwsCfg.IPAMSubnetsIDs,
		SubnetsTags:                  p.AwsCfg.IPAMSubnetsTags,
		ParallelAllocWorkers:         p.Cfg.ParallelAllocWorkers,
		LimitIPAMAPIBurst:            p.Cfg.LimitIPAMAPIBurst,
		LimitIPAMAPIQPS:              p.Cfg.LimitIPAMAPIQPS,
	}

	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				if err := allocator.Init(ctx, p.Logger, p.EC2Metrics); err != nil {
					return fmt.Errorf("unable to init AWS allocator: %w", err)
				}

				nm, err := allocator.Start(ctx, &ciliumNodeUpdateImplementation{p.Clientset}, p.IPAMMetrics)
				if err != nil {
					return fmt.Errorf("unable to start AWS allocator: %w", err)
				}

				p.JobGroup.Add(p.NodeWatcherFactory(nm))

				return nil
			},
		},
	)
}
