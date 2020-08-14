// Copyright 2018 Authors of Cilium
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
	"net"
	"os"

	"github.com/cilium/cilium/pkg/aws/endpoints"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

const (
	awsLogLevel         = aws.LogOff // For debugging pourposes can be set to aws.LogDebugWithSigning
	awsDefaultRegionKey = "AWS_DEFAULT_REGION"
	awsDefaultRegion    = "eu-west-1"
)

var (
	policySecurityGroupIDKey = aws.String("instance.group-id")
	policySecurityGroupName  = aws.String("instance.group-name")
	policyEC2Labelskey       = "tag"
)

func init() {
	api.RegisterToGroupsProvider(api.AWSProvider, GetIPsFromGroup)
}

// GetIPsFromGroup will return the list of the ips for the given group filter
func GetIPsFromGroup(ctx context.Context, group *api.ToGroups) ([]net.IP, error) {
	result := []net.IP{}
	if group.AWS == nil {
		return result, fmt.Errorf("no aws data available")
	}
	return getInstancesIpsFromFilter(ctx, group.AWS)
}

// initializeAWSAccount retrieve the env variables from the runtime and it
// iniliazes the account in the specified region.
func initializeAWSAccount(region string) (*aws.Config, error) {
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize aws connector: %s", err)
	}
	cfg.Region = region
	cfg.LogLevel = awsLogLevel
	cfg.EndpointResolver = aws.EndpointResolverFunc(endpoints.Resolver)
	return &cfg, nil
}

// getInstancesFromFilter returns the instances IPs in aws EC2 filter by the
// given filter
func getInstancesIpsFromFilter(ctx context.Context, filter *api.AWSGroup) ([]net.IP, error) {
	region := filter.Region
	if filter.Region == "" {
		region = getDefaultRegion()
	}
	input := &ec2.DescribeInstancesInput{}
	for labelKey, labelValue := range filter.Labels {
		newFilter := ec2.Filter{
			Name:   aws.String(fmt.Sprintf("%s:%s", policyEC2Labelskey, labelKey)),
			Values: []string{labelValue},
		}
		input.Filters = append(input.Filters, newFilter)
	}
	if len(filter.SecurityGroupsIds) > 0 {
		newFilter := ec2.Filter{
			Name:   policySecurityGroupIDKey,
			Values: filter.SecurityGroupsIds,
		}
		input.Filters = append(input.Filters, newFilter)
	}
	if len(filter.SecurityGroupsNames) > 0 {
		newFilter := ec2.Filter{
			Name:   policySecurityGroupName,
			Values: filter.SecurityGroupsNames,
		}
		input.Filters = append(input.Filters, newFilter)
	}
	cfg, err := initializeAWSAccount(region)
	if err != nil {
		return []net.IP{}, err
	}
	svc := ec2.New(*cfg)
	req := svc.DescribeInstancesRequest(input)
	result, err := req.Send(ctx)
	if err != nil {
		return []net.IP{}, fmt.Errorf("Cannot retrieve aws information: %s", err)
	}
	return awsDumpIpsFromRequest(result.DescribeInstancesOutput), nil
}

// getDefaultRegion returns the given region of the default one.
// @TODO retrieve the region from aws metadata.
func getDefaultRegion() string {
	val := os.Getenv(awsDefaultRegionKey)
	if val != "" {
		return val
	}
	return awsDefaultRegion
}

func awsDumpIpsFromRequest(req *ec2.DescribeInstancesOutput) []net.IP {
	result := []net.IP{}
	for _, reservation := range req.Reservations {
		for _, instance := range reservation.Instances {
			for _, iface := range instance.NetworkInterfaces {
				for _, ifaceIP := range iface.PrivateIpAddresses {
					result = append(result, net.ParseIP(string(*ifaceIP.PrivateIpAddress)))
					if ifaceIP.Association != nil {
						result = append(result, net.ParseIP(string(*ifaceIP.Association.PublicIp)))
					}
				}
			}
		}
	}
	return result
}
