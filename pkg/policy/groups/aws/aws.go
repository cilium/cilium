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

	cilium_ec2 "github.com/cilium/cilium/pkg/aws/ec2"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
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

// getInstancesFromFilter returns the instances IPs in aws EC2 filter by the
// given filter
func getInstancesIpsFromFilter(ctx context.Context, filter *api.AWSGroup) ([]net.IP, error) {
	var result []ec2_types.Reservation
	input := &ec2.DescribeInstancesInput{}

	cfg, err := cilium_ec2.NewConfig(ctx)
	if err != nil {
		return nil, err
	}
	ec2Client := ec2.NewFromConfig(cfg)

	for labelKey, labelValue := range filter.Labels {
		newFilter := ec2_types.Filter{
			Name:   aws.String(fmt.Sprintf("%s:%s", policyEC2Labelskey, labelKey)),
			Values: []string{labelValue},
		}
		input.Filters = append(input.Filters, newFilter)
	}
	if len(filter.SecurityGroupsIds) > 0 {
		newFilter := ec2_types.Filter{
			Name:   policySecurityGroupIDKey,
			Values: filter.SecurityGroupsIds,
		}
		input.Filters = append(input.Filters, newFilter)
	}
	if len(filter.SecurityGroupsNames) > 0 {
		newFilter := ec2_types.Filter{
			Name:   policySecurityGroupName,
			Values: filter.SecurityGroupsNames,
		}
		input.Filters = append(input.Filters, newFilter)
	}

	paginator := ec2.NewDescribeInstancesPaginator(ec2Client, input)
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("Cannot retrieve aws information: %w", err)
		}
		result = append(result, output.Reservations...)
	}
	return extractIPs(result), nil
}

func extractIPs(reservations []ec2_types.Reservation) []net.IP {
	result := []net.IP{}
	for _, reservation := range reservations {
		for _, instance := range reservation.Instances {
			for _, iface := range instance.NetworkInterfaces {
				for _, ifaceIP := range iface.PrivateIpAddresses {
					result = append(result, net.ParseIP(aws.ToString(ifaceIP.PrivateIpAddress)))
					if ifaceIP.Association != nil {
						result = append(result, net.ParseIP(aws.ToString(ifaceIP.Association.PublicIp)))
					}
				}
			}
		}
	}
	return result
}
