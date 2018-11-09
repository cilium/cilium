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
	"fmt"
	"net"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	awsLogLevel            = aws.LogOff // For debugging pourposes can be set to aws.LogDebugWithSigning
	AWS_DEFAULT_REGION_KEY = "AWS_DEFAULT_REGION"
	AWS_DEFAULT_REGION     = "eu-west-1"
)

var (
	POLICY_SECURITY_GROUP_ID_KEY = aws.String("instance.group-id")
	POLICY_SECURITY_GROUP_NAME   = aws.String("instance.group-name")
	POLICY_EC2_LABELS_KEY        = "tag"
)

func init() {
	api.RegisterToGroupsProvider(api.AWSPROVIDER, GetIPsFromGroup)
}

// GetIpsFromGroup will return the list of the ips for the given group filter
func GetIPsFromGroup(group *api.ToGroups) ([]net.IP, error) {
	result := []net.IP{}
	if group.Aws == nil {
		return result, fmt.Errorf("no aws data available")
	}
	ips, err := GetInstancesIpsFromFilter(group.Aws)
	return ips, err
}

// InitializeAWSAccount retrieve the env variables from the runtime and it
// iniliazes the account in the specified region.
func InitializeAWSAccount(region string) (*aws.Config, error) {
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize aws connector: %s", err)
	}
	cfg.Region = GetDefaultRegion()
	cfg.LogLevel = awsLogLevel
	return &cfg, nil
}

//GetInstancesFromFilter returns the instances IPs in aws EC2 filter by the
//given filter
func GetInstancesIpsFromFilter(filter *api.AWSGroups) ([]net.IP, error) {
	region := filter.Region
	if filter.Region != "" {
		region = GetDefaultRegion()
	}
	input := &ec2.DescribeInstancesInput{}
	for labelKey, labelValue := range filter.Labels {
		newFilter := ec2.Filter{
			Name:   aws.String(fmt.Sprintf("%s:%s", POLICY_EC2_LABELS_KEY, labelKey)),
			Values: []string{labelValue},
		}
		input.Filters = append(input.Filters, newFilter)
	}
	if len(filter.SecurityGroupsIds) > 0 {
		newFilter := ec2.Filter{
			Name:   POLICY_SECURITY_GROUP_ID_KEY,
			Values: filter.SecurityGroupsIds,
		}
		input.Filters = append(input.Filters, newFilter)
	}
	if len(filter.SecurityGroupsNames) > 0 {
		newFilter := ec2.Filter{
			Name:   POLICY_SECURITY_GROUP_NAME,
			Values: filter.SecurityGroupsNames,
		}
		input.Filters = append(input.Filters, newFilter)
	}
	cfg, err := InitializeAWSAccount(region)
	if err != nil {
		return []net.IP{}, err
	}
	svc := ec2.New(*cfg)
	req := svc.DescribeInstancesRequest(input)
	result, err := req.Send()
	if err != nil {
		return []net.IP{}, fmt.Errorf("Cannot retrieve aws information: %s", err)
	}
	return awsDumpIpsFromRequest(result), nil
}

// GetDefaultRegion returns the given region of the default one.
// @TODO retrieve the region from aws metadata.
func GetDefaultRegion() string {
	val := os.Getenv(AWS_DEFAULT_REGION_KEY)
	if val != "" {
		return val
	}
	return AWS_DEFAULT_REGION
}

func awsDumpIpsFromRequest(req *ec2.DescribeInstancesOutput) []net.IP {
	result := []net.IP{}
	if len(req.Reservations) == 0 {
		return result
	}
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
