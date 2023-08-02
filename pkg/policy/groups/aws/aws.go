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
	policySecurityGroupIDKey = aws.String("group-id")
	policySecurityGroupName  = aws.String("group-name")
	policyEC2Labelskey       = "tag"
)

func init() {
	api.RegisterToGroupsProvider(api.AWSProvider, GetIPsFromGroup)
}

// GetIPsFromGroup will return the list of the IPs for the given group filter
func GetIPsFromGroup(ctx context.Context, group *api.ToGroups) ([]netip.Addr, error) {
	result := []netip.Addr{}
	if group.AWS == nil {
		return result, fmt.Errorf("no aws data available")
	}

	cfg, err := cilium_ec2.NewConfig(ctx)
	if err != nil {
		return nil, err
	}
	ec2Client := ec2.NewFromConfig(cfg)

	// If the group has a security group filter, add the IPs from the network interfaces
	if len(group.AWS.SecurityGroupsIds) > 0 || len(group.AWS.SecurityGroupsNames) > 0 {
		ips, err := getNetworkInterfaceIpsFromFilter(ctx, group.AWS, ec2Client)
		if err != nil {
			return nil, err
		}
		result = append(result, ips...)
	}

	// If the group has a label filter, add the IPs from the instances
	if len(group.AWS.Labels) > 0 {
		ips, err := getInstancesIpsFromFilter(ctx, group.AWS, ec2Client)
		if err != nil {
			return nil, err
		}
		result = append(result, ips...)
	}

	return result, nil
}

// getNetworkInterfaceIpsFromFilter returns the IPs from the network interfaces for
// the given security group filter
func getNetworkInterfaceIpsFromFilter(ctx context.Context, filter *api.AWSGroup, ec2Client *ec2.Client) ([]netip.Addr, error) {
	result := []netip.Addr{}
	input := &ec2.DescribeNetworkInterfacesInput{}

	if len(filter.SecurityGroupsIds) > 0 {
		input.Filters = append(input.Filters, ec2_types.Filter{
			Name:   policySecurityGroupIDKey,
			Values: filter.SecurityGroupsIds,
		})
	}
	if len(filter.SecurityGroupsNames) > 0 {
		input.Filters = append(input.Filters, ec2_types.Filter{
			Name:   policySecurityGroupName,
			Values: filter.SecurityGroupsNames,
		})
	}

	paginator := ec2.NewDescribeNetworkInterfacesPaginator(ec2Client, input)
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve aws network interface information: %w", err)
		}
		// functionally equivalent to extractIPs, we return private IPs and associated public IPs
		for _, iface := range output.NetworkInterfaces {
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
	return result, nil
}

// getInstancesIpsFromFilter returns IPs from matching instances for the given
// label filter
func getInstancesIpsFromFilter(ctx context.Context, filter *api.AWSGroup, ec2Client *ec2.Client) ([]netip.Addr, error) {
	var result []ec2_types.Reservation
	input := &ec2.DescribeInstancesInput{}

	for labelKey, labelValue := range filter.Labels {
		newFilter := ec2_types.Filter{
			Name:   aws.String(policyEC2Labelskey + ":" + labelKey),
			Values: []string{labelValue},
		}
		input.Filters = append(input.Filters, newFilter)
	}

	paginator := ec2.NewDescribeInstancesPaginator(ec2Client, input)
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve aws ec2 instance information: %w", err)
		}
		result = append(result, output.Reservations...)
	}
	return extractIPs(result), nil
}

// extractIPs returns the private and associated public IPs from the given reservations
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
