// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	httperr "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/wait"

	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/spanstat"
)

const (
	AttachNetworkInterface    = "AttachNetworkInterface"
	CreateNetworkInterface    = "CreateNetworkInterface"
	DescribeInstances         = "DescribeInstances"
	DescribeNetworkInterfaces = "DescribeNetworkInterfaces"
	DescribeVpcs              = "DescribeVpcs"
	DescribeVSwitches         = "DescribeVSwitches"
	ListTagResources          = "ListTagResources"
)

var maxAttachRetries = wait.Backoff{
	Duration: 2500 * time.Millisecond,
	Factor:   1,
	Jitter:   0.1,
	Steps:    6,
	Cap:      0,
}

// Client an AlibabaCloud API client
type Client struct {
	vpcClient        *vpc.Client
	ecsClient        *ecs.Client
	limiter          *helpers.APILimiter
	metricsAPI       MetricsAPI
	instancesFilters map[string]string
}

// MetricsAPI represents the metrics maintained by the AlibabaCloud API client
type MetricsAPI interface {
	helpers.MetricsAPI
	ObserveAPICall(call, status string, duration float64)
}

// NewClient create the client
func NewClient(vpcClient *vpc.Client, client *ecs.Client, metrics MetricsAPI, rateLimit float64, burst int, filters map[string]string) *Client {
	return &Client{
		vpcClient:        vpcClient,
		ecsClient:        client,
		limiter:          helpers.NewAPILimiter(metrics, rateLimit, burst),
		metricsAPI:       metrics,
		instancesFilters: filters,
	}
}

// GetInstance returns the instance including its ENIs by the given instanceID
func (c *Client) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance := ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}

	networkInterfaceSets, err := c.describeNetworkInterfacesByInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaceSets {
		ifId := iface.NetworkInterfaceId
		_, eni, err := parseENI(&iface, vpcs, subnets)
		if err != nil {
			return nil, err
		}

		instance.Interfaces[ifId] = ipamTypes.InterfaceRevision{
			Resource: eni,
		}
	}
	return &instance, nil
}

// GetInstances returns the list of all instances including their ENIs as instanceMap
func (c *Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	var networkInterfaceSets []ecs.NetworkInterfaceSet
	var err error

	if len(c.instancesFilters) > 0 {
		networkInterfaceSets, err = c.describeNetworkInterfacesFromInstances(ctx)
	} else {
		networkInterfaceSets, err = c.describeNetworkInterfaces(ctx)
	}
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaceSets {
		id, eni, err := parseENI(&iface, vpcs, subnets)
		if err != nil {
			return nil, err
		}

		instances.Update(id, ipamTypes.InterfaceRevision{
			Resource: eni,
		})
	}
	return instances, nil
}

// GetVSwitches returns all ecs vSwitches as a subnetMap
func (c *Client) GetVSwitches(ctx context.Context) (ipamTypes.SubnetMap, error) {
	var result ipamTypes.SubnetMap
	for i := 1; ; {
		req := vpc.CreateDescribeVSwitchesRequest()
		req.PageNumber = requests.NewInteger(i)
		req.PageSize = requests.NewInteger(50)
		c.limiter.Limit(ctx, DescribeVSwitches)
		resp, err := c.vpcClient.DescribeVSwitches(req)
		if err != nil {
			return nil, err
		}
		if len(resp.VSwitches.VSwitch) == 0 {
			break
		}
		if result == nil {
			result = make(ipamTypes.SubnetMap, resp.TotalCount)
		}

		for _, v := range resp.VSwitches.VSwitch {
			_, ipnet, err := net.ParseCIDR(v.CidrBlock)
			if err != nil {
				return nil, err
			}
			result[v.VSwitchId] = &ipamTypes.Subnet{
				ID:                 v.VSwitchId,
				Name:               v.VSwitchName,
				CIDR:               cidr.NewCIDR(ipnet),
				AvailabilityZone:   v.ZoneId,
				VirtualNetworkID:   v.VpcId,
				AvailableAddresses: int(v.AvailableIpAddressCount),
				Tags:               map[string]string{},
			}
			for _, tag := range v.Tags.Tag {
				result[v.VSwitchId].Tags[tag.Key] = tag.Value
			}
		}
		if resp.TotalCount < resp.PageNumber*resp.PageSize {
			break
		}
		i++
	}

	return result, nil
}

// GetVPC get vpc by id
func (c *Client) GetVPC(ctx context.Context, vpcID string) (*ipamTypes.VirtualNetwork, error) {
	req := vpc.CreateDescribeVpcsRequest()
	req.VpcId = vpcID
	c.limiter.Limit(ctx, DescribeVpcs)
	resp, err := c.vpcClient.DescribeVpcs(req)
	if err != nil {
		return nil, err
	}
	if len(resp.Vpcs.Vpc) == 0 {
		return nil, fmt.Errorf("cannot find VPC by ID %s", vpcID)
	}

	return &ipamTypes.VirtualNetwork{
		ID:          resp.Vpcs.Vpc[0].VpcId,
		PrimaryCIDR: resp.Vpcs.Vpc[0].CidrBlock,
		CIDRs:       resp.Vpcs.Vpc[0].SecondaryCidrBlocks.SecondaryCidrBlock,
	}, nil
}

// GetVPCs retrieves and returns all VPCs
func (c *Client) GetVPCs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	var result ipamTypes.VirtualNetworkMap
	for i := 1; ; {
		req := vpc.CreateDescribeVpcsRequest()
		req.PageNumber = requests.NewInteger(i)
		req.PageSize = requests.NewInteger(50)
		resp, err := c.vpcClient.DescribeVpcs(req)
		if err != nil {
			return nil, err
		}
		if len(resp.Vpcs.Vpc) == 0 {
			break
		}
		if result == nil {
			result = make(ipamTypes.VirtualNetworkMap, resp.TotalCount)
		}
		for _, v := range resp.Vpcs.Vpc {
			result[v.VpcId] = &ipamTypes.VirtualNetwork{
				ID:          v.VpcId,
				PrimaryCIDR: v.CidrBlock,
				CIDRs:       v.SecondaryCidrBlocks.SecondaryCidrBlock,
			}
		}
		if resp.TotalCount < resp.PageNumber*resp.PageSize {
			break
		}
		i++
	}
	return result, nil
}

// GetInstanceTypes returns all the known ECS instance types in the configured region
func (c *Client) GetInstanceTypes(ctx context.Context) ([]ecs.InstanceType, error) {
	var result []ecs.InstanceType
	req := ecs.CreateDescribeInstanceTypesRequest()
	// When there are many instance types, some instance limits can not be queried,
	// so use NextToken and MaxResults for paging query.
	// MaxResults is the number of entries on each page, the maximum value of this parameter is 100.
	// Ref: https://www.alibabacloud.com/help/en/elastic-compute-service/latest/describeinstancetypes
	req.MaxResults = requests.NewInteger(100)
	for {
		resp, err := c.ecsClient.DescribeInstanceTypes(req)
		if err != nil {
			return nil, err
		}

		result = append(result, resp.InstanceTypes.InstanceType...)

		if resp.NextToken == "" {
			break
		}
		req.NextToken = resp.NextToken
	}

	return result, nil
}

// GetSecurityGroups return all sg
func (c *Client) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	var result types.SecurityGroupMap
	for i := 1; ; {
		req := ecs.CreateDescribeSecurityGroupsRequest()
		req.PageNumber = requests.NewInteger(i)
		req.PageSize = requests.NewInteger(50)
		resp, err := c.ecsClient.DescribeSecurityGroups(req)
		if err != nil {
			return nil, err
		}
		if len(resp.SecurityGroups.SecurityGroup) == 0 {
			break
		}
		if result == nil {
			result = make(types.SecurityGroupMap, resp.TotalCount)
		}
		for _, v := range resp.SecurityGroups.SecurityGroup {
			result[v.VpcId] = &types.SecurityGroup{
				ID:    v.SecurityGroupId,
				VPCID: v.VpcId,
				Tags:  parseECSTags(v.Tags.Tag),
			}
		}
		if resp.TotalCount < resp.PageNumber*resp.PageSize {
			break
		}
		i++
	}
	return result, nil
}

// DescribeNetworkInterface get ENI by id
func (c *Client) DescribeNetworkInterface(ctx context.Context, eniID string) (*ecs.NetworkInterfaceSet, error) {
	req := ecs.CreateDescribeNetworkInterfacesRequest()
	req.NetworkInterfaceId = &[]string{eniID}
	resp, err := c.ecsClient.DescribeNetworkInterfaces(req)
	if err != nil {
		return nil, err
	}
	if len(resp.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
		return nil, fmt.Errorf("failed to find eni %s", eniID)
	}
	return &resp.NetworkInterfaceSets.NetworkInterfaceSet[0], nil
}

// CreateNetworkInterface creates an ENI with the given parameters
func (c *Client) CreateNetworkInterface(ctx context.Context, secondaryPrivateIPCount int, vSwitchID string, groups []string, tags map[string]string) (string, *eniTypes.ENI, error) {
	req := ecs.CreateCreateNetworkInterfaceRequest()
	// SecondaryPrivateIpAddressCount is optional but must not be zero
	if secondaryPrivateIPCount > 0 {
		req.SecondaryPrivateIpAddressCount = requests.NewInteger(secondaryPrivateIPCount)
	}
	req.VSwitchId = vSwitchID
	req.SecurityGroupIds = &groups
	reqTag := make([]ecs.CreateNetworkInterfaceTag, 0, len(tags))
	for k, v := range tags {
		reqTag = append(reqTag, ecs.CreateNetworkInterfaceTag{
			Key:   k,
			Value: v,
		})
	}
	req.Tag = &reqTag

	c.limiter.Limit(ctx, CreateNetworkInterface)

	sinceStart := spanstat.Start()
	resp, err := c.ecsClient.CreateNetworkInterface(req)
	c.metricsAPI.ObserveAPICall(CreateNetworkInterface, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", nil, err
	}

	var privateIPSets []eniTypes.PrivateIPSet
	for _, p := range resp.PrivateIpSets.PrivateIpSet {
		privateIPSets = append(privateIPSets, eniTypes.PrivateIPSet{
			Primary:          p.Primary,
			PrivateIpAddress: p.PrivateIpAddress,
		})
	}
	eni := &eniTypes.ENI{
		NetworkInterfaceID: resp.NetworkInterfaceId,
		MACAddress:         resp.MacAddress,
		Type:               resp.Type,
		SecurityGroupIDs:   resp.SecurityGroupIds.SecurityGroupId,
		VPC: eniTypes.VPC{
			VPCID: resp.VpcId,
		},
		ZoneID: resp.ZoneId,
		VSwitch: eniTypes.VSwitch{
			VSwitchID: resp.VSwitchId,
		},
		PrimaryIPAddress: resp.PrivateIpAddress,
		PrivateIPSets:    privateIPSets,
		Tags:             parseECSTags(resp.Tags.Tag),
	}
	return resp.NetworkInterfaceId, eni, nil
}

// AttachNetworkInterface attaches a previously created ENI to an instance
func (c *Client) AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	req := ecs.CreateAttachNetworkInterfaceRequest()
	req.InstanceId = instanceID
	req.NetworkInterfaceId = eniID
	c.limiter.Limit(ctx, AttachNetworkInterface)
	sinceStart := spanstat.Start()
	_, err := c.ecsClient.AttachNetworkInterface(req)
	c.metricsAPI.ObserveAPICall(AttachNetworkInterface, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return err
	}
	return nil
}

// WaitENIAttached check ENI is attached to ECS and return attached ECS instanceID
func (c *Client) WaitENIAttached(ctx context.Context, eniID string) (string, error) {
	instanceID := ""
	err := wait.ExponentialBackoffWithContext(ctx, maxAttachRetries, func(ctx context.Context) (done bool, err error) {
		eni, err := c.DescribeNetworkInterface(ctx, eniID)
		if err != nil {
			return false, err
		}
		if eni.Status == "InUse" {
			instanceID = eni.InstanceId
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return "", err
	}
	return instanceID, nil
}

// DeleteNetworkInterface deletes an ENI with the specified ID
func (c *Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	req := ecs.CreateDeleteNetworkInterfaceRequest()
	req.NetworkInterfaceId = eniID
	_, err := c.ecsClient.DeleteNetworkInterface(req)
	if err != nil {
		return err
	}
	return nil
}

// AssignPrivateIPAddresses assigns the specified number of secondary IP
// return allocated IPs
func (c *Client) AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error) {
	req := ecs.CreateAssignPrivateIpAddressesRequest()
	req.NetworkInterfaceId = eniID
	req.SecondaryPrivateIpAddressCount = requests.NewInteger(toAllocate)
	resp, err := c.ecsClient.AssignPrivateIpAddresses(req)
	if err != nil {
		return nil, err
	}
	return resp.AssignedPrivateIpAddressesSet.PrivateIpSet.PrivateIpAddress, nil
}

// PrUnassignivateIPAddresses unassign specified IP addresses from ENI
// should not provide Primary IP
func (c *Client) UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) error {
	req := ecs.CreateUnassignPrivateIpAddressesRequest()
	req.NetworkInterfaceId = eniID
	req.PrivateIpAddress = &addresses
	_, err := c.ecsClient.UnassignPrivateIpAddresses(req)
	return err
}

func (c *Client) describeNetworkInterfaces(ctx context.Context) ([]ecs.NetworkInterfaceSet, error) {
	var result []ecs.NetworkInterfaceSet
	req := ecs.CreateDescribeNetworkInterfacesRequest()
	req.MaxResults = requests.NewInteger(500)

	for {
		c.limiter.Limit(ctx, DescribeNetworkInterfaces)
		resp, err := c.ecsClient.DescribeNetworkInterfaces(req)
		if err != nil {
			return nil, err
		}

		result = append(result, resp.NetworkInterfaceSets.NetworkInterfaceSet...)

		if resp.NextToken == "" {
			break
		} else {
			req.NextToken = resp.NextToken
		}
	}

	return result, nil
}

// describeNetworkInterfacesFromInstances lists all ENIs matching filtered ECS instances.
// Due to a limitation in the DescribeInstances API, we can only retrieve up to 1,000 instances
// when filtering by tags directly. To overcome this limitation, an alternative approach is
// implemented in 3 steps:
// 1. Filter out matching instance ids with ListTagResources
// 2. Split instance ids into batches of 100 and send parallel DescribeInstances requests
// 3. Split eni ids from the instances and send parallel DescribeNetworkInterfaces requests
// https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-listtagresources
// https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-describeinstances
// https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-describenetworkinterfaces
func (c *Client) describeNetworkInterfacesFromInstances(ctx context.Context) ([]ecs.NetworkInterfaceSet, error) {
	var result []ecs.NetworkInterfaceSet

	// Get filtered instance IDs
	tagResouces, err := c.EcsListTagResources(ctx, c.instancesFilters)
	if err != nil {
		return nil, err
	}
	instanceIds := make([]string, 0, len(tagResouces))
	for _, t := range tagResouces {
		instanceIds = append(instanceIds, t.ResourceId)
	}
	// The response of ListTagResources can have duplicate instanceId
	slices.Unique(instanceIds)

	if len(instanceIds) == 0 {
		return result, nil
	}

	// DescribeInstances and retrieve the ENI id list. DescribeInstances accepts 100 instance IDs
	// at most, so split instanceIds into batches of 100 and send parallel requests for performance.
	// Return error if any request fails.
	g := new(errgroup.Group)
	respChan := make(chan *ecs.DescribeInstancesResponse, (len(instanceIds)/100)+1)

	for i := 0; i < len(instanceIds); i += 100 {
		idx := i
		endIdx := min(idx+100, len(instanceIds))
		quotedIds := make([]string, endIdx-idx)
		for i := idx; i < endIdx; i++ {
			quotedIds[i-idx] = fmt.Sprintf(`"%s"`, instanceIds[i])
		}

		g.Go(func() error {
			req := ecs.CreateDescribeInstancesRequest()
			// format: ["xxx","xxx","xxx"]
			req.InstanceIds = fmt.Sprintf("[%s]", strings.Join(quotedIds, ","))
			req.PageSize = requests.NewInteger(100)
			c.limiter.Limit(ctx, DescribeInstances)
			resp, err := c.ecsClient.DescribeInstances(req)
			if err != nil {
				return err
			}
			respChan <- resp
			return nil
		})
	}

	err = g.Wait()
	close(respChan)
	if err != nil {
		return nil, err
	}

	// Collect interface IDs from instance details
	interfaceIds := []string{}
	for resp := range respChan {
		for _, instance := range resp.Instances.Instance {
			for _, iface := range instance.NetworkInterfaces.NetworkInterface {
				interfaceIds = append(interfaceIds, iface.NetworkInterfaceId)
			}
		}
	}

	if len(interfaceIds) == 0 {
		return result, nil
	}

	// DescribeNetworkInterfaces accepts 100 interface IDs at most,
	// so split interfaceIds into batches of 100 and send parallel requests for performance.
	// Return error if any request fails.
	g = new(errgroup.Group)
	ifaceRespChan := make(chan *ecs.DescribeNetworkInterfacesResponse, (len(interfaceIds)/100)+1)
	for i := 0; i < len(interfaceIds); i += 100 {
		idx := i
		endIdx := min(idx+100, len(interfaceIds))
		g.Go(func() error {
			req := ecs.CreateDescribeNetworkInterfacesRequest()
			ifaceSlice := interfaceIds[idx:endIdx]
			req.NetworkInterfaceId = &ifaceSlice
			req.PageSize = requests.NewInteger(100)
			c.limiter.Limit(ctx, DescribeNetworkInterfaces)
			resp, err := c.ecsClient.DescribeNetworkInterfaces(req)
			if err != nil {
				return err
			}
			ifaceRespChan <- resp
			return nil
		})
	}

	err = g.Wait()
	close(ifaceRespChan)
	if err != nil {
		return nil, err
	}

	for resp := range ifaceRespChan {
		result = append(result, resp.NetworkInterfaceSets.NetworkInterfaceSet...)
	}

	return result, nil
}

func (c *Client) describeNetworkInterfacesByInstance(ctx context.Context, instanceID string) ([]ecs.NetworkInterfaceSet, error) {
	var result []ecs.NetworkInterfaceSet

	for i := 1; ; {
		req := ecs.CreateDescribeNetworkInterfacesRequest()
		req.PageNumber = requests.NewInteger(i)
		req.PageSize = requests.NewInteger(1000)
		req.InstanceId = instanceID
		c.limiter.Limit(ctx, DescribeNetworkInterfaces)
		resp, err := c.ecsClient.DescribeNetworkInterfaces(req)
		if err != nil {
			return nil, err
		}
		if len(resp.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
			break
		}

		result = append(result, resp.NetworkInterfaceSets.NetworkInterfaceSet...)

		if resp.TotalCount < resp.PageNumber*resp.PageSize {
			break
		}
		i++
	}

	return result, nil
}

func (c *Client) EcsListTagResources(ctx context.Context, tags map[string]string) ([]ecs.TagResource, error) {
	var result []ecs.TagResource

	req := ecs.CreateListTagResourcesRequest()
	req.ResourceType = "instance"
	reqTags := []ecs.ListTagResourcesTag{}
	for k, v := range tags {
		reqTags = append(reqTags, ecs.ListTagResourcesTag{
			Key:   k,
			Value: v,
		})
	}
	req.Tag = &reqTags
	c.limiter.Limit(ctx, ListTagResources)

	for {
		resp, err := c.ecsClient.ListTagResources(req)
		if err != nil {
			return nil, err
		}
		result = append(result, resp.TagResources.TagResource...)
		if resp.NextToken == "" {
			break
		} else {
			req.NextToken = resp.NextToken
		}
	}

	return result, nil
}

// deriveStatus returns a status string based on the HTTP response provided by
// the AlibabaCloud API server. If no specific status is provided, either "OK" or
// "Failed" is returned based on the error variable.
func deriveStatus(err error) string {
	var respErr httperr.Error
	if errors.As(err, &respErr) {
		return respErr.ErrorCode()
	}

	if err != nil {
		return "Failed"
	}

	return "OK"
}

// parseENI parses a ecs.NetworkInterface as returned by the ecs service API,
// converts it into a eniTypes.ENI object
func parseENI(iface *ecs.NetworkInterfaceSet, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (instanceID string, eni *eniTypes.ENI, err error) {
	var privateIPSets []eniTypes.PrivateIPSet
	for _, p := range iface.PrivateIpSets.PrivateIpSet {
		privateIPSets = append(privateIPSets, eniTypes.PrivateIPSet{
			Primary:          p.Primary,
			PrivateIpAddress: p.PrivateIpAddress,
		})
	}

	eni = &eniTypes.ENI{
		NetworkInterfaceID: iface.NetworkInterfaceId,
		MACAddress:         iface.MacAddress,
		Type:               iface.Type,
		InstanceID:         iface.InstanceId,
		SecurityGroupIDs:   iface.SecurityGroupIds.SecurityGroupId,
		VPC: eniTypes.VPC{
			VPCID: iface.VpcId,
		},
		ZoneID: iface.ZoneId,
		VSwitch: eniTypes.VSwitch{
			VSwitchID: iface.VSwitchId,
		},
		PrimaryIPAddress: iface.PrivateIpAddress,
		PrivateIPSets:    privateIPSets,
		Tags:             parseECSTags(iface.Tags.Tag),
	}
	vpc, ok := vpcs[iface.VpcId]
	if ok {
		eni.VPC.CIDRBlock = vpc.PrimaryCIDR
		eni.VPC.SecondaryCIDRs = vpc.CIDRs
	}

	subnet, ok := subnets[iface.VSwitchId]
	if ok && subnet.CIDR != nil {
		eni.VSwitch.CIDRBlock = subnet.CIDR.String()
	}
	return iface.InstanceId, eni, nil
}

// parseECSTags convert ECS Tags to ipam Tags
func parseECSTags(tags []ecs.Tag) ipamTypes.Tags {
	result := make(ipamTypes.Tags, len(tags))
	for _, tag := range tags {
		result[tag.TagKey] = tag.TagValue
	}
	return result
}
