// Copyright 2019 Authors of Cilium
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

package ec2

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/aws/endpoints"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// Client represents an EC2 API client
type Client struct {
	ec2Client      *ec2.Client
	limiter        *helpers.ApiLimiter
	metricsAPI     MetricsAPI
	subnetsFilters []ec2.Filter
}

// MetricsAPI represents the metrics maintained by the AWS API client
type MetricsAPI interface {
	helpers.MetricsAPI
	ObserveAPICall(call, status string, duration float64)
}

// NewClient returns a new EC2 client
func NewClient(ec2Client *ec2.Client, metrics MetricsAPI, rateLimit float64, burst int, subnetsFilters []ec2.Filter) *Client {
	return &Client{
		ec2Client:      ec2Client,
		metricsAPI:     metrics,
		limiter:        helpers.NewApiLimiter(metrics, rateLimit, burst),
		subnetsFilters: subnetsFilters,
	}
}

// NewConfig returns a new aws.Config configured with the correct region + endpoint resolver
func NewConfig() (aws.Config, error) {
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to load AWS configuration: %w", err)
	}

	metadataClient := ec2metadata.New(cfg)
	instance, err := metadataClient.GetInstanceIdentityDocument(context.TODO())
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to retrieve instance identity document: %w", err)
	}

	cfg.Region = instance.Region
	cfg.EndpointResolver = aws.EndpointResolverFunc(endpoints.Resolver)

	return cfg, nil
}

// NewSubnetsFilters transforms a map of tags and values and a slice of subnets
// into a slice of ec2.Filter adequate to filter AWS subnets.
func NewSubnetsFilters(tags map[string]string, ids []string) []ec2.Filter {
	filters := make([]ec2.Filter, 0, len(tags)+1)

	for k, v := range tags {
		filters = append(filters, ec2.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", k)),
			Values: []string{v},
		})
	}

	if len(ids) > 0 {
		filters = append(filters, ec2.Filter{
			Name:   aws.String("subnet-id"),
			Values: ids,
		})
	}

	return filters
}

// deriveStatus returns a status string based on the HTTP response provided by
// the AWS API server. If no specific status is provided, either "OK" or
// "Failed" is returned based on the error variable.
func deriveStatus(req *aws.Request, err error) string {
	if req.HTTPResponse != nil {
		return req.HTTPResponse.Status
	}

	if err != nil {
		return "Failed"
	}

	return "OK"
}

// describeNetworkInterfaces lists all ENIs
func (c *Client) describeNetworkInterfaces(ctx context.Context, subnets ipamTypes.SubnetMap) ([]ec2.NetworkInterface, error) {
	var (
		networkInterfaces []ec2.NetworkInterface
		interfacesFilters []ec2.Filter
		nextToken         string
	)

	for {
		c.limiter.Limit(ctx, "DescribeNetworkInterfaces")
		req := &ec2.DescribeNetworkInterfacesInput{}
		if nextToken != "" {
			req.NextToken = &nextToken
		}

		if len(c.subnetsFilters) > 0 {
			subnetsIDs := make([]string, 0, len(subnets))
			for id := range subnets {
				subnetsIDs = append(subnetsIDs, id)
			}
			interfacesFilters = append(interfacesFilters, ec2.Filter{
				Name:   aws.String("subnet-id"),
				Values: subnetsIDs,
			})
			req.Filters = interfacesFilters
		}

		sinceStart := spanstat.Start()
		listReq := c.ec2Client.DescribeNetworkInterfacesRequest(req)
		response, err := listReq.Send(ctx)
		c.metricsAPI.ObserveAPICall("DescribeNetworkInterfaces", deriveStatus(listReq.Request, err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}

		networkInterfaces = append(networkInterfaces, response.NetworkInterfaces...)

		if response.NextToken == nil || *response.NextToken == "" {
			break
		} else {
			nextToken = *response.NextToken
		}
	}

	return networkInterfaces, nil
}

// parseENI parses a ec2.NetworkInterface as returned by the EC2 service API,
// converts it into a eniTypes.ENI object
func parseENI(iface *ec2.NetworkInterface, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (instanceID string, eni *eniTypes.ENI, err error) {
	if iface.PrivateIpAddress == nil {
		err = fmt.Errorf("ENI has no IP address")
		return
	}

	eni = &eniTypes.ENI{
		IP:             *iface.PrivateIpAddress,
		SecurityGroups: []string{},
		Addresses:      []string{},
	}

	if iface.MacAddress != nil {
		eni.MAC = *iface.MacAddress
	}

	if iface.NetworkInterfaceId != nil {
		eni.ID = *iface.NetworkInterfaceId
	}

	if iface.Description != nil {
		eni.Description = *iface.Description
	}

	if iface.Attachment != nil {
		if iface.Attachment.DeviceIndex != nil {
			eni.Number = int(*iface.Attachment.DeviceIndex)
		}

		if iface.Attachment.InstanceId != nil {
			instanceID = *iface.Attachment.InstanceId
		}
	}

	if iface.SubnetId != nil {
		eni.Subnet.ID = *iface.SubnetId

		if subnets != nil {
			if subnet, ok := subnets[eni.Subnet.ID]; ok && subnet.CIDR != nil {
				eni.Subnet.CIDR = subnet.CIDR.String()
			}
		}
	}

	if iface.VpcId != nil {
		eni.VPC.ID = *iface.VpcId

		if vpcs != nil {
			if vpc, ok := vpcs[eni.VPC.ID]; ok {
				eni.VPC.PrimaryCIDR = vpc.PrimaryCIDR
			}
		}
	}

	for _, ip := range iface.PrivateIpAddresses {
		if ip.PrivateIpAddress != nil {
			eni.Addresses = append(eni.Addresses, *ip.PrivateIpAddress)
		}
	}

	for _, g := range iface.Groups {
		if g.GroupId != nil {
			eni.SecurityGroups = append(eni.SecurityGroups, *g.GroupId)
		}
	}

	return
}

// GetInstances returns the list of all instances including their ENIs as
// instanceMap
func (c *Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	networkInterfaces, err := c.describeNetworkInterfaces(ctx, subnets)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		id, eni, err := parseENI(&iface, vpcs, subnets)
		if err != nil {
			return nil, err
		}

		if id != "" {
			instances.Update(id, ipamTypes.InterfaceRevision{Resource: eni})
		}
	}

	return instances, nil
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs(ctx context.Context) ([]ec2.Vpc, error) {
	var vpcs []ec2.Vpc

	c.limiter.Limit(ctx, "DescribeVpcs")
	req := &ec2.DescribeVpcsInput{}

	sinceStart := spanstat.Start()
	listReq := c.ec2Client.DescribeVpcsRequest(req)
	response, err := listReq.Send(ctx)
	c.metricsAPI.ObserveAPICall("DescribeVpcs", deriveStatus(listReq.Request, err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	vpcs = append(vpcs, response.Vpcs...)

	return vpcs, nil
}

// GetVpcs retrieves and returns all Vpcs
func (c *Client) GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}

	vpcList, err := c.describeVpcs(ctx)
	if err != nil {
		return nil, err
	}

	for _, v := range vpcList {
		vpc := &ipamTypes.VirtualNetwork{ID: *v.VpcId}

		if v.CidrBlock != nil {
			vpc.PrimaryCIDR = *v.CidrBlock
		}

		vpcs[vpc.ID] = vpc
	}

	return vpcs, nil
}

// describeSubnets lists all subnets
func (c *Client) describeSubnets(ctx context.Context) ([]ec2.Subnet, error) {
	c.limiter.Limit(ctx, "DescribeSubnets")

	sinceStart := spanstat.Start()
	reqInput := &ec2.DescribeSubnetsInput{}
	if len(c.subnetsFilters) > 0 {
		reqInput.Filters = c.subnetsFilters
	}
	listReq := c.ec2Client.DescribeSubnetsRequest(reqInput)
	result, err := listReq.Send(ctx)
	c.metricsAPI.ObserveAPICall("DescribeSubnets", deriveStatus(listReq.Request, err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	return result.Subnets, nil
}

// GetSubnets returns all EC2 subnets as a subnetMap
func (c *Client) GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	subnetList, err := c.describeSubnets(ctx)
	if err != nil {
		return nil, err
	}

	for _, s := range subnetList {
		c, err := cidr.ParseCIDR(*s.CidrBlock)
		if err != nil {
			continue
		}

		subnet := &ipamTypes.Subnet{
			ID:                 *s.SubnetId,
			CIDR:               c,
			AvailableAddresses: int(*s.AvailableIpAddressCount),
			Tags:               map[string]string{},
		}

		if s.AvailabilityZone != nil {
			subnet.AvailabilityZone = *s.AvailabilityZone
		}

		if s.VpcId != nil {
			subnet.VirtualNetworkID = *s.VpcId
		}

		for _, tag := range s.Tags {
			if *tag.Key == "Name" {
				subnet.Name = *tag.Value
			}
			subnet.Tags[*tag.Key] = *tag.Value
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

// CreateNetworkInterface creates an ENI with the given parameters
func (c *Client) CreateNetworkInterface(ctx context.Context, toAllocate int64, subnetID, desc string, groups []string) (string, *eniTypes.ENI, error) {
	createReq := &ec2.CreateNetworkInterfaceInput{
		Description:                    &desc,
		SecondaryPrivateIpAddressCount: &toAllocate,
		SubnetId:                       &subnetID,
	}
	createReq.Groups = append(createReq.Groups, groups...)

	c.limiter.Limit(ctx, "CreateNetworkInterface")
	sinceStart := spanstat.Start()
	create := c.ec2Client.CreateNetworkInterfaceRequest(createReq)
	resp, err := create.Send(ctx)
	c.metricsAPI.ObserveAPICall("CreateNetworkInterface", deriveStatus(create.Request, err), sinceStart.Seconds())
	if err != nil {
		return "", nil, err
	}

	_, eni, err := parseENI(resp.NetworkInterface, nil, nil)
	if err != nil {
		// The error is ignored on purpose. The allocation itself has
		// succeeded. The ability to parse and return the ENI
		// information is optional. Returning the ENI ID is sufficient
		// to allow for the caller to retrieve the ENI information via
		// the API or wait for a regular sync to fetch the information.
		return *resp.NetworkInterface.NetworkInterfaceId, nil, nil
	}

	return eni.ID, eni, nil

}

// DeleteNetworkInterface deletes an ENI with the specified ID
func (c *Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	delReq := &ec2.DeleteNetworkInterfaceInput{}
	delReq.NetworkInterfaceId = &eniID

	c.limiter.Limit(ctx, "DeleteNetworkInterface")
	sinceStart := spanstat.Start()
	req := c.ec2Client.DeleteNetworkInterfaceRequest(delReq)
	_, err := req.Send(ctx)
	c.metricsAPI.ObserveAPICall("DeleteNetworkInterface", deriveStatus(req.Request, err), sinceStart.Seconds())
	return err
}

// AttachNetworkInterface attaches a previously created ENI to an instance
func (c *Client) AttachNetworkInterface(ctx context.Context, index int64, instanceID, eniID string) (string, error) {
	attachReq := &ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        &index,
		InstanceId:         &instanceID,
		NetworkInterfaceId: &eniID,
	}

	c.limiter.Limit(ctx, "AttachNetworkInterface")
	sinceStart := spanstat.Start()
	attach := c.ec2Client.AttachNetworkInterfaceRequest(attachReq)
	attachResp, err := attach.Send(ctx)
	c.metricsAPI.ObserveAPICall("AttachNetworkInterface", deriveStatus(attach.Request, err), sinceStart.Seconds())
	if err != nil {
		return "", err
	}

	return *attachResp.AttachmentId, nil
}

// ModifyNetworkInterface modifies the attributes of an ENI
func (c *Client) ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error {
	changes := &ec2.NetworkInterfaceAttachmentChanges{
		AttachmentId:        &attachmentID,
		DeleteOnTermination: &deleteOnTermination,
	}

	modifyReq := &ec2.ModifyNetworkInterfaceAttributeInput{
		Attachment:         changes,
		NetworkInterfaceId: &eniID,
	}

	c.limiter.Limit(ctx, "ModifyNetworkInterfaceAttribute")
	sinceStart := spanstat.Start()
	modify := c.ec2Client.ModifyNetworkInterfaceAttributeRequest(modifyReq)
	_, err := modify.Send(ctx)
	c.metricsAPI.ObserveAPICall("ModifyNetworkInterface", deriveStatus(modify.Request, err), sinceStart.Seconds())
	return err
}

// AssignPrivateIpAddresses assigns the specified number of secondary IP
// addresses
func (c *Client) AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int64) error {
	request := ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             &eniID,
		SecondaryPrivateIpAddressCount: &addresses,
	}

	c.limiter.Limit(ctx, "AssignPrivateIpAddresses")
	sinceStart := spanstat.Start()
	req := c.ec2Client.AssignPrivateIpAddressesRequest(&request)
	_, err := req.Send(ctx)
	c.metricsAPI.ObserveAPICall("AssignPrivateIpAddresses", deriveStatus(req.Request, err), sinceStart.Seconds())
	return err
}

// UnassignPrivateIpAddresses unassigns specified IP addresses from ENI
func (c *Client) UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error {
	request := ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: &eniID,
		PrivateIpAddresses: addresses,
	}

	c.limiter.Limit(ctx, "UnassignPrivateIpAddresses")
	sinceStart := spanstat.Start()
	req := c.ec2Client.UnassignPrivateIpAddressesRequest(&request)
	_, err := req.Send(ctx)
	c.metricsAPI.ObserveAPICall("UnassignPrivateIpAddresses", deriveStatus(req.Request, err), sinceStart.Seconds())
	return err
}

// TagENI creates the specified tags on the ENI
func (c *Client) TagENI(ctx context.Context, eniID string, eniTags map[string]string) error {
	request := ec2.CreateTagsInput{
		Resources: []string{eniID},
		Tags:      createAWSTagSlice(eniTags),
	}
	c.limiter.Limit(ctx, "CreateTags")
	sinceStart := spanstat.Start()
	req := c.ec2Client.CreateTagsRequest(&request)
	_, err := req.Send(ctx)
	c.metricsAPI.ObserveAPICall("CreateTags", deriveStatus(req.Request, err), sinceStart.Seconds())
	return err
}

func createAWSTagSlice(tags map[string]string) []ec2.Tag {
	awsTags := make([]ec2.Tag, 0, len(tags))
	for k, v := range tags {
		awsTag := ec2.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		awsTags = append(awsTags, awsTag)
	}

	return awsTags
}

func (c *Client) describeSecurityGroups(ctx context.Context) ([]ec2.SecurityGroup, error) {
	c.limiter.Limit(ctx, "DescribeSecurityGroups")
	sinceStart := spanstat.Start()
	req := c.ec2Client.DescribeSecurityGroupsRequest(&ec2.DescribeSecurityGroupsInput{})
	response, err := req.Send(ctx)
	c.metricsAPI.ObserveAPICall("DescribeSecurityGroups", deriveStatus(req.Request, err), sinceStart.Seconds())
	if err != nil {
		return []ec2.SecurityGroup{}, err
	}

	return response.SecurityGroups, nil
}

// GetSecurityGroups returns all EC2 security groups as a SecurityGroupMap
func (c *Client) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	securityGroups := types.SecurityGroupMap{}

	secGroupList, err := c.describeSecurityGroups(ctx)
	if err != nil {
		return securityGroups, err
	}

	for _, secGroup := range secGroupList {
		id := aws.StringValue(secGroup.GroupId)

		securityGroup := &types.SecurityGroup{
			ID:    id,
			VpcID: aws.StringValue(secGroup.VpcId),
			Tags:  map[string]string{},
		}
		for _, tag := range secGroup.Tags {
			key := aws.StringValue(tag.Key)
			value := aws.StringValue(tag.Value)
			securityGroup.Tags[key] = value
		}

		securityGroups[id] = securityGroup
	}

	return securityGroups, nil
}

// GetInstanceTypes returns all the known EC2 instance types in the configured region
func (c *Client) GetInstanceTypes(ctx context.Context) ([]ec2.InstanceTypeInfo, error) {
	c.limiter.Limit(ctx, "DescribeInstanceTypes")
	sinceStart := spanstat.Start()
	instanceTypeInfos := []ec2.InstanceTypeInfo{}
	describeInstanceTypes := &ec2.DescribeInstanceTypesInput{}
	req := c.ec2Client.DescribeInstanceTypesRequest(describeInstanceTypes)
	describeInstanceTypesResponse, err := req.Send(ctx)
	c.metricsAPI.ObserveAPICall("DescribeInstanceTypes", deriveStatus(req.Request, err), sinceStart.Seconds())
	if err != nil {
		return instanceTypeInfos, err
	}

	instanceTypeInfos = append(instanceTypeInfos, describeInstanceTypesResponse.InstanceTypes...)

	for describeInstanceTypesResponse.NextToken != nil {
		describeInstanceTypes := &ec2.DescribeInstanceTypesInput{
			NextToken: describeInstanceTypesResponse.NextToken,
		}
		req = c.ec2Client.DescribeInstanceTypesRequest(describeInstanceTypes)
		describeInstanceTypesResponse, err = req.Send(ctx)
		if err != nil {
			return instanceTypeInfos, err
		}

		instanceTypeInfos = append(instanceTypeInfos, describeInstanceTypesResponse.InstanceTypes...)
	}

	return instanceTypeInfos, nil
}
