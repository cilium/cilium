// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aws

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	cilium_ec2 "github.com/cilium/cilium/pkg/aws/ec2"
	"github.com/cilium/cilium/pkg/policy/api"
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
func GetIPsFromGroup(ctx context.Context, group *api.ToGroups) ([]netip.Addr, error) {
	result := []netip.Addr{}
	if group.AWS == nil {
		return result, fmt.Errorf("no aws data available")
	}
	return getInstancesIpsFromFilter(ctx, group.AWS)
}

// getInstancesFromFilter returns the instances IPs in aws EC2 filter by the
// given filter
func getInstancesIpsFromFilter(ctx context.Context, filter *api.AWSGroup) ([]netip.Addr, error) {
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

func extractIPs(reservations []ec2_types.Reservation) []netip.Addr {
	result := []netip.Addr{}
	for _, reservation := range reservations {
		for _, instance := range reservation.Instances {
			for _, iface := range instance.NetworkInterfaces {
				for _, ifaceIP := range iface.PrivateIpAddresses {
					addr, err := netip.ParseAddr(aws.ToString(ifaceIP.PrivateIpAddress))
					if err != nil {
						continue
					}
					result = append(result, addr)
					if ifaceIP.Association != nil {
						addr, err = netip.ParseAddr(aws.ToString(ifaceIP.Association.PublicIp))
						if err != nil {
							continue
						}
						result = append(result, addr)
					}
				}
			}
		}
	}
	return result
}
