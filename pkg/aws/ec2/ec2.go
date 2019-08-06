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
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"golang.org/x/time/rate"
)

// Client represents an EC2 API client
type Client struct {
	ec2Client  *ec2.EC2
	limiter    *rate.Limiter
	metricsAPI metricsAPI
}

type metricsAPI interface {
	ObserveEC2APICall(call, status string, duration float64)
	ObserveEC2RateLimit(operation string, duration time.Duration)
}

// NewClient returns a new EC2 client
func NewClient(ec2Client *ec2.EC2, metrics metricsAPI, rateLimit float64, burst int) *Client {
	return &Client{
		ec2Client:  ec2Client,
		metricsAPI: metrics,
		limiter:    rate.NewLimiter(rate.Limit(rateLimit), burst),
	}
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

func (c *Client) rateLimit(operation string) {
	r := c.limiter.Reserve()
	if delay := r.Delay(); delay != time.Duration(0) && delay != rate.InfDuration {
		c.metricsAPI.ObserveEC2RateLimit(operation, delay)
		c.limiter.Wait(context.TODO())
	}
}

// describeNetworkInterfaces lists all ENIs
func (c *Client) describeNetworkInterfaces() ([]ec2.NetworkInterface, error) {
	var (
		networkInterfaces []ec2.NetworkInterface
		nextToken         string
	)

	for {
		c.rateLimit("DescribeNetworkInterfaces")
		req := &ec2.DescribeNetworkInterfacesInput{}
		if nextToken != "" {
			req.NextToken = &nextToken
		}

		sinceStart := spanstat.Start()
		listReq := c.ec2Client.DescribeNetworkInterfacesRequest(req)
		response, err := listReq.Send()
		c.metricsAPI.ObserveEC2APICall("DescribeNetworkInterfaces", deriveStatus(listReq.Request, err), sinceStart.Seconds())
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
// converts it into a v2. ENI object
func parseENI(iface *ec2.NetworkInterface, vpcs types.VpcMap, subnets types.SubnetMap) (instanceID string, eni *v2.ENI, err error) {
	if iface.PrivateIpAddress == nil {
		err = fmt.Errorf("ENI has no IP address")
		return
	}

	eni = &v2.ENI{
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
			if subnet, ok := subnets[eni.Subnet.ID]; ok {
				eni.Subnet.CIDR = subnet.CIDR
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
func (c *Client) GetInstances(vpcs types.VpcMap, subnets types.SubnetMap) (types.InstanceMap, error) {
	instances := types.InstanceMap{}

	networkInterfaces, err := c.describeNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		id, eni, err := parseENI(&iface, vpcs, subnets)
		if err != nil {
			return nil, err
		}

		if id != "" {
			instances.Add(id, eni)
		}
	}

	return instances, nil
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs() ([]ec2.Vpc, error) {
	var vpcs []ec2.Vpc

	c.rateLimit("DescribeVpcs")
	req := &ec2.DescribeVpcsInput{}

	sinceStart := spanstat.Start()
	listReq := c.ec2Client.DescribeVpcsRequest(req)
	response, err := listReq.Send()
	c.metricsAPI.ObserveEC2APICall("DescribeVpcs", deriveStatus(listReq.Request, err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	vpcs = append(vpcs, response.Vpcs...)

	return vpcs, nil
}

// GetVpcs retrieves and returns all Vpcs
func (c *Client) GetVpcs() (types.VpcMap, error) {
	vpcs := types.VpcMap{}

	vpcList, err := c.describeVpcs()
	if err != nil {
		return nil, err
	}

	for _, v := range vpcList {
		vpc := &types.Vpc{ID: *v.VpcId}

		if v.CidrBlock != nil {
			vpc.PrimaryCIDR = *v.CidrBlock
		}

		vpcs[vpc.ID] = vpc
	}

	return vpcs, nil
}

// describeSubnets lists all subnets
func (c *Client) describeSubnets() ([]ec2.Subnet, error) {
	sinceStart := spanstat.Start()
	listReq := c.ec2Client.DescribeSubnetsRequest(&ec2.DescribeSubnetsInput{})
	result, err := listReq.Send()
	c.metricsAPI.ObserveEC2APICall("DescribeSubnets", deriveStatus(listReq.Request, err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	return result.Subnets, nil
}

// GetSubnets returns all EC2 subnets as a subnetMap
func (c *Client) GetSubnets() (types.SubnetMap, error) {
	subnets := types.SubnetMap{}

	subnetList, err := c.describeSubnets()
	if err != nil {
		return nil, err
	}

	for _, s := range subnetList {
		subnet := &types.Subnet{
			ID:                 *s.SubnetId,
			CIDR:               *s.CidrBlock,
			AvailableAddresses: int(*s.AvailableIpAddressCount),
			Tags:               map[string]string{},
		}

		if s.AvailabilityZone != nil {
			subnet.AvailabilityZone = *s.AvailabilityZone
		}

		if s.VpcId != nil {
			subnet.VpcID = *s.VpcId
		}

		for _, tag := range s.Tags {
			if *tag.Key == "Name" {
				subnet.Name = *tag.Value
			} else {
				subnet.Tags[*tag.Key] = *tag.Value
			}
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

// CreateNetworkInterface creates an ENI with the given parameters
func (c *Client) CreateNetworkInterface(toAllocate int64, subnetID, desc string, groups []string) (string, *v2.ENI, error) {
	createReq := &ec2.CreateNetworkInterfaceInput{
		Description:                    &desc,
		SecondaryPrivateIpAddressCount: &toAllocate,
		SubnetId:                       &subnetID,
	}
	for _, grp := range groups {
		createReq.Groups = append(createReq.Groups, grp)
	}

	c.rateLimit("CreateNetworkInterface")
	sinceStart := spanstat.Start()
	create := c.ec2Client.CreateNetworkInterfaceRequest(createReq)
	resp, err := create.Send()
	c.metricsAPI.ObserveEC2APICall("CreateNetworkInterfaceRequest", deriveStatus(create.Request, err), sinceStart.Seconds())
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
func (c *Client) DeleteNetworkInterface(eniID string) error {
	delReq := &ec2.DeleteNetworkInterfaceInput{}
	delReq.NetworkInterfaceId = &eniID

	c.rateLimit("DeleteNetworkInterface")
	sinceStart := spanstat.Start()
	req := c.ec2Client.DeleteNetworkInterfaceRequest(delReq)
	_, err := req.Send()
	c.metricsAPI.ObserveEC2APICall("DeleteNetworkInterface", deriveStatus(req.Request, err), sinceStart.Seconds())
	return err
}

// AttachNetworkInterface attaches a previously created ENI to an instance
func (c *Client) AttachNetworkInterface(index int64, instanceID, eniID string) (string, error) {
	attachReq := &ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        &index,
		InstanceId:         &instanceID,
		NetworkInterfaceId: &eniID,
	}

	c.rateLimit("AttachNetworkInterface")
	sinceStart := spanstat.Start()
	attach := c.ec2Client.AttachNetworkInterfaceRequest(attachReq)
	attachResp, err := attach.Send()
	c.metricsAPI.ObserveEC2APICall("AttachNetworkInterface", deriveStatus(attach.Request, err), sinceStart.Seconds())
	if err != nil {
		return "", err
	}

	return *attachResp.AttachmentId, nil
}

// ModifyNetworkInterface modifies the attributes of an ENI
func (c *Client) ModifyNetworkInterface(eniID, attachmentID string, deleteOnTermination bool) error {
	changes := &ec2.NetworkInterfaceAttachmentChanges{
		AttachmentId:        &attachmentID,
		DeleteOnTermination: &deleteOnTermination,
	}

	modifyReq := &ec2.ModifyNetworkInterfaceAttributeInput{
		Attachment:         changes,
		NetworkInterfaceId: &eniID,
	}

	c.rateLimit("ModifyNetworkInterfaceAttribute")
	sinceStart := spanstat.Start()
	modify := c.ec2Client.ModifyNetworkInterfaceAttributeRequest(modifyReq)
	_, err := modify.Send()
	c.metricsAPI.ObserveEC2APICall("ModifyNetworkInterface", deriveStatus(modify.Request, err), sinceStart.Seconds())
	return err
}

// AssignPrivateIpAddresses assigns the specified number of secondary IP
// addresses
func (c *Client) AssignPrivateIpAddresses(eniID string, addresses int64) error {
	request := ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             &eniID,
		SecondaryPrivateIpAddressCount: &addresses,
	}

	c.rateLimit("AssignPrivateIpAddresses")
	sinceStart := spanstat.Start()
	req := c.ec2Client.AssignPrivateIpAddressesRequest(&request)
	_, err := req.Send()
	c.metricsAPI.ObserveEC2APICall("AssignPrivateIpAddresses", deriveStatus(req.Request, err), sinceStart.Seconds())
	return err
}
