// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ec2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	"github.com/cilium/cilium/pkg/api/helpers"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"
)

const (
	SubnetFullErrMsgStr = "There aren't sufficient free Ipv4 addresses or prefixes"

	// InsufficientPrefixesInSubnetStr AWS error code for insufficient /28 prefixes in a subnet, possibly due to
	// fragmentation
	InsufficientPrefixesInSubnetStr = "InsufficientCidrBlocks"

	// InvalidParameterValueStr sort of catch-all error code from AWS to indicate request params are invalid. Often,
	// requires looking at the error message to get the actual reason. See SubnetFullErrMsgStr for example.
	InvalidParameterValueStr = "InvalidParameterValue"

	// OperationNotPermittedStr indicates the request returned too many results without sufficient filtering or pagination
	OperationNotPermittedStr = "OperationNotPermitted"

	AssignPrivateIpAddresses        = "AssignPrivateIpAddresses"
	AssociateAddress                = "AssociateAddress"
	AttachNetworkInterface          = "AttachNetworkInterface"
	CreateNetworkInterface          = "CreateNetworkInterface"
	DeleteNetworkInterface          = "DeleteNetworkInterface"
	DescribeAddresses               = "DescribeAddresses"
	DescribeInstances               = "DescribeInstances"
	DescribeInstanceTypes           = "DescribeInstanceTypes"
	DescribeNetworkInterfaces       = "DescribeNetworkInterfaces"
	DescribeSecurityGroups          = "DescribeSecurityGroups"
	DescribeSubnets                 = "DescribeSubnets"
	DescribeVpcs                    = "DescribeVpcs"
	DescribeRouteTables             = "DescribeRouteTables"
	ModifyNetworkInterface          = "ModifyNetworkInterface"
	ModifyNetworkInterfaceAttribute = "ModifyNetworkInterfaceAttribute"
	UnassignPrivateIpAddresses      = "UnassignPrivateIpAddresses"
)

var syslogAttr = []any{logfields.LogSubsys, "ec2"}

// Client represents an EC2 API client
type Client struct {
	logger              *slog.Logger
	ec2Client           *ec2.Client
	limiter             *helpers.APILimiter
	metricsAPI          MetricsAPI
	subnetsFilters      []ec2_types.Filter
	routeTableFilters   []ec2_types.Filter
	instancesFilters    []ec2_types.Filter
	eniTagSpecification ec2_types.TagSpecification
	usePrimary          bool
	maxResultsPerCall   int32 // Maximum results per API call; 0 means let AWS decide
}

// MetricsAPI represents the metrics maintained by the AWS API client
type MetricsAPI interface {
	helpers.MetricsAPI
	ObserveAPICall(call, status string, duration float64)
}

// NewClient returns a new EC2 client
func NewClient(logger *slog.Logger, ec2Client *ec2.Client, metrics MetricsAPI, rateLimit float64, burst int, subnetsFilters, instancesFilters []ec2_types.Filter, eniTags map[string]string, usePrimary bool, maxResultsPerCall int32) *Client {
	eniTagSpecification := ec2_types.TagSpecification{
		ResourceType: ec2_types.ResourceTypeNetworkInterface,
		Tags:         createAWSTagSlice(eniTags),
	}

	return &Client{
		logger:              logger.With(syslogAttr...),
		ec2Client:           ec2Client,
		metricsAPI:          metrics,
		limiter:             helpers.NewAPILimiter(metrics, rateLimit, burst),
		subnetsFilters:      subnetsFilters,
		instancesFilters:    instancesFilters,
		eniTagSpecification: eniTagSpecification,
		usePrimary:          usePrimary,
		maxResultsPerCall:   maxResultsPerCall,
	}
}

// getMaxResults returns the current maxResultsPerCall value.
// Returns nil if 0 (let AWS decide), otherwise returns pointer to the value.
func (c *Client) getMaxResults() *int32 {
	if c.maxResultsPerCall == 0 {
		return nil
	}
	return aws.Int32(c.maxResultsPerCall)
}

// isOperationNotPermitted checks if an error is an AWS OperationNotPermitted error,
// which indicates the request returned too many results without sufficient filtering or pagination.
func isOperationNotPermitted(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == OperationNotPermittedStr
	}
	return false
}

// switchToPagination checks if an error requires switching to paginated requests.
// If OperationNotPermitted is detected and we're currently unpaginated (maxResultsPerCall=0),
// it logs a warning and switches to paginated requests (maxResultsPerCall=1000).
// Returns true if a switch was made and the request should be retried.
func (c *Client) switchToPagination(err error) bool {
	if !isOperationNotPermitted(err) {
		return false
	}

	// If already using pagination, no switch needed
	if c.maxResultsPerCall > 0 {
		return false
	}

	// Switch to pagination
	c.maxResultsPerCall = 1000
	c.logger.Warn("AWS API returned OperationNotPermitted, the operator will automatically switch to paginated requests. "+
		"To disable this warning, set --aws-max-results-per-call=1000",
		logfields.MaxResults, c.maxResultsPerCall)
	return true
}

// NewConfig returns a new aws.Config configured with the correct region
func NewConfig(ctx context.Context) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to load AWS configuration: %w", err)
	}

	metadataClient := imds.NewFromConfig(cfg)
	instance, err := metadataClient.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to retrieve instance identity document: %w", err)
	}

	cfg.Region = instance.Region
	cfg.Retryer = func() aws.Retryer {
		return retry.NewStandard(func(o *retry.StandardOptions) {
			// We only want to rely on internal Cilium rate-limiting
			o.RateLimiter = ratelimit.None
		})
	}

	return cfg, nil
}

// NewSubnetsFilters transforms a map of tags and values and a slice of subnets
// into a slice of ec2.Filter adequate to filter AWS subnets.
func NewSubnetsFilters(tags map[string]string, ids []string) []ec2_types.Filter {
	filters := make([]ec2_types.Filter, 0, len(tags)+1)

	for k, v := range tags {
		filters = append(filters, ec2_types.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", k)),
			Values: []string{v},
		})
	}

	if len(ids) > 0 {
		filters = append(filters, ec2_types.Filter{
			Name:   aws.String("subnet-id"),
			Values: ids,
		})
	}

	return filters
}

// NewTagsFilter transforms a map of tags and values
// into a slice of ec2.Filter adequate to filter resources based on tags.
func NewTagsFilter(tags map[string]string) []ec2_types.Filter {
	filters := make([]ec2_types.Filter, 0, len(tags))

	for k, v := range tags {
		filters = append(filters, ec2_types.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", k)),
			Values: []string{v},
		})
	}

	return filters
}

// MergeTags merges all tags into a newly created map. Duplicate tags are
// overwritten by rightmost argument.
func MergeTags(tagMaps ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, tagMap := range tagMaps {
		maps.Copy(merged, tagMap)
	}
	return merged
}

// deriveStatus returns a status string based on the HTTP response provided by
// the AWS API server. If no specific status is provided, either "OK" or
// "Failed" is returned based on the error variable.
func deriveStatus(err error) string {
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.Response.Status
	}

	if err != nil {
		return "Failed"
	}

	return "OK"
}

func DetectEKSClusterName(ctx context.Context, cfg aws.Config) (string, error) {
	instance, err := imds.NewFromConfig(cfg).GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve instance identity document: %w", err)
	}

	const eksClusterNameTag = "aws:eks:cluster-name"
	tags, err := ec2.NewFromConfig(cfg).DescribeTags(ctx, &ec2.DescribeTagsInput{
		Filters: []ec2_types.Filter{
			{Name: aws.String("resource-type"), Values: []string{"instance"}},
			{Name: aws.String("resource-id"), Values: []string{instance.InstanceID}},
			{Name: aws.String("key"), Values: []string{eksClusterNameTag}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve instance identity document: %w", err)
	}
	if len(tags.Tags) == 0 || aws.ToString(tags.Tags[0].Key) != eksClusterNameTag {
		return "", fmt.Errorf("tag not found: %s", eksClusterNameTag)
	}

	return aws.ToString(tags.Tags[0].Value), nil
}

func (c *Client) GetDetachedNetworkInterfaces(ctx context.Context, tags ipamTypes.Tags, maxResults int32) ([]string, error) {
retry:
	for {
		result := make([]string, 0, int(maxResults))
		input := &ec2.DescribeNetworkInterfacesInput{
			Filters: NewTagsFilter(tags),
		}
		for _, subnetFilter := range c.subnetsFilters {
			if aws.ToString(subnetFilter.Name) == "subnet-id" {
				input.Filters = append(input.Filters, subnetFilter)
			}
		}

		input.Filters = append(input.Filters, ec2_types.Filter{
			Name:   aws.String("status"),
			Values: []string{"available"},
		})

		// Set MaxResults based on current configuration (nil means let AWS decide)
		input.MaxResults = c.getMaxResults()

		paginator := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2Client, input)
		for paginator.HasMorePages() {
			c.limiter.Limit(ctx, DescribeNetworkInterfaces)
			sinceStart := spanstat.Start()
			output, err := paginator.NextPage(ctx)
			c.metricsAPI.ObserveAPICall(DescribeNetworkInterfaces, deriveStatus(err), sinceStart.Seconds())
			if err != nil {
				// If OperationNotPermitted and we switch to pagination, retry the entire request
				if c.switchToPagination(err) {
					continue retry
				}
				return nil, err
			}
			for _, eni := range output.NetworkInterfaces {
				if len(result) >= int(maxResults) {
					return result, nil
				}
				result = append(result, aws.ToString(eni.NetworkInterfaceId))
			}
		}

		return result, nil
	}
}

// describeNetworkInterfaces lists all ENIs
func (c *Client) describeNetworkInterfaces(ctx context.Context, subnets ipamTypes.SubnetMap) ([]ec2_types.NetworkInterface, error) {
retry:
	for {
		var result []ec2_types.NetworkInterface
		input := &ec2.DescribeNetworkInterfacesInput{
			// Filters out ipv6-only ENIs. For now we require that every interface
			// has a primary IPv4 address.
			Filters: []ec2_types.Filter{
				{
					Name:   aws.String("private-ip-address"),
					Values: []string{"*"},
				},
			},
		}
		if len(c.subnetsFilters) > 0 {
			subnetsIDs := make([]string, 0, len(subnets))
			for id := range subnets {
				subnetsIDs = append(subnetsIDs, id)
			}
			input.Filters = append(input.Filters, ec2_types.Filter{
				Name:   aws.String("subnet-id"),
				Values: subnetsIDs,
			})
		}

		// Set MaxResults based on current configuration (nil means let AWS decide)
		input.MaxResults = c.getMaxResults()

		paginator := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2Client, input)
		for paginator.HasMorePages() {
			c.limiter.Limit(ctx, DescribeNetworkInterfaces)
			sinceStart := spanstat.Start()
			output, err := paginator.NextPage(ctx)
			c.metricsAPI.ObserveAPICall(DescribeNetworkInterfaces, deriveStatus(err), sinceStart.Seconds())
			if err != nil {
				// If OperationNotPermitted and we switch to pagination, retry the entire request
				if c.switchToPagination(err) {
					continue retry
				}
				return nil, err
			}
			result = append(result, output.NetworkInterfaces...)
		}

		return result, nil
	}
}

// describeNetworkInterfacesByInstance gets ENIs on the given instance
func (c *Client) describeNetworkInterfacesByInstance(ctx context.Context, instanceID string) ([]ec2_types.NetworkInterface, error) {
	var result []ec2_types.NetworkInterface

	input := &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2_types.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: []string{instanceID},
			},
		},
	}
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2Client, input)
	for paginator.HasMorePages() {
		c.limiter.Limit(ctx, DescribeNetworkInterfaces)
		sinceStart := spanstat.Start()
		output, err := paginator.NextPage(ctx)
		c.metricsAPI.ObserveAPICall(DescribeNetworkInterfaces, deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}
		result = append(result, output.NetworkInterfaces...)
	}
	return result, nil
}

// describeNetworkInterfacesFromInstances lists all ENIs matching filtered EC2 instances
func (c *Client) describeNetworkInterfacesFromInstances(ctx context.Context) ([]ec2_types.NetworkInterface, error) {
	enisFromInstances := make(map[string]struct{})

	instanceAttrs := &ec2.DescribeInstancesInput{}
	if len(c.instancesFilters) > 0 {
		instanceAttrs.Filters = c.instancesFilters
	}

	paginator := ec2.NewDescribeInstancesPaginator(c.ec2Client, instanceAttrs)
	for paginator.HasMorePages() {
		c.limiter.Limit(ctx, DescribeInstances)
		sinceStart := spanstat.Start()
		output, err := paginator.NextPage(ctx)
		c.metricsAPI.ObserveAPICall(DescribeInstances, deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}

		// loop the instances and add all ENIs to the list
		for _, r := range output.Reservations {
			for _, i := range r.Instances {
				for _, ifs := range i.NetworkInterfaces {
					enisFromInstances[aws.ToString(ifs.NetworkInterfaceId)] = struct{}{}
				}
			}
		}
	}

	enisListFromInstances := make([]string, 0, len(enisFromInstances))
	for k := range enisFromInstances {
		enisListFromInstances = append(enisListFromInstances, k)
	}

retry:
	for {
		var result []ec2_types.NetworkInterface

		ENIAttrs := &ec2.DescribeNetworkInterfacesInput{
			// Filters out ipv6-only ENIs. For now we require that every interface
			// has a primary IPv4 address.
			Filters: []ec2_types.Filter{
				{
					Name:   aws.String("private-ip-address"),
					Values: []string{"*"},
				},
			},
		}
		if len(enisListFromInstances) > 0 {
			// MaxResults is incompatible with NetworkInterfaceIds, so we can only use specific IDs here
			ENIAttrs.NetworkInterfaceIds = enisListFromInstances
		} else {
			// Set MaxResults based on current configuration (nil means let AWS decide)
			ENIAttrs.MaxResults = c.getMaxResults()
		}

		ENIPaginator := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2Client, ENIAttrs)
		for ENIPaginator.HasMorePages() {
			c.limiter.Limit(ctx, DescribeNetworkInterfaces)
			sinceStart := spanstat.Start()
			output, err := ENIPaginator.NextPage(ctx)
			c.metricsAPI.ObserveAPICall(DescribeNetworkInterfaces, deriveStatus(err), sinceStart.Seconds())
			if err != nil {
				// If OperationNotPermitted and we switch to pagination, retry the entire request
				// But only if not using NetworkInterfaceIds (which is incompatible with MaxResults)
				if len(enisListFromInstances) == 0 && c.switchToPagination(err) {
					continue retry
				}
				return nil, err
			}
			result = append(result, output.NetworkInterfaces...)
		}

		return result, nil
	}
}

// parseENI parses a ec2.NetworkInterface as returned by the EC2 service API,
// converts it into a eniTypes.ENI object
func parseENI(iface *ec2_types.NetworkInterface, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, usePrimary bool) (instanceID string, eni *eniTypes.ENI, err error) {
	if iface.PrivateIpAddress == nil {
		err = fmt.Errorf("ENI has no IP address")
		return
	}

	eni = &eniTypes.ENI{
		IP:             aws.ToString(iface.PrivateIpAddress),
		SecurityGroups: []string{},
		Addresses:      []string{},
	}

	if iface.MacAddress != nil {
		eni.MAC = aws.ToString(iface.MacAddress)
	}

	if iface.NetworkInterfaceId != nil {
		eni.ID = aws.ToString(iface.NetworkInterfaceId)
	}

	if iface.Description != nil {
		eni.Description = aws.ToString(iface.Description)
	}

	if iface.Attachment != nil {
		eni.Number = int(aws.ToInt32(iface.Attachment.DeviceIndex))

		if iface.Attachment.InstanceId != nil {
			instanceID = aws.ToString(iface.Attachment.InstanceId)
		}
	}

	if iface.SubnetId != nil {
		eni.Subnet.ID = aws.ToString(iface.SubnetId)

		if subnets != nil {
			if subnet, ok := subnets[eni.Subnet.ID]; ok && subnet.CIDR.IsValid() {
				eni.Subnet.CIDR = subnet.CIDR.String()
			}
		}
	}

	if iface.VpcId != nil {
		eni.VPC.ID = aws.ToString(iface.VpcId)

		if vpcs != nil {
			if vpc, ok := vpcs[eni.VPC.ID]; ok {
				eni.VPC.PrimaryCIDR = vpc.PrimaryCIDR
				eni.VPC.CIDRs = vpc.CIDRs
			}
		}
	}

	for _, ip := range iface.PrivateIpAddresses {
		if !usePrimary && ip.Primary != nil && aws.ToBool(ip.Primary) {
			continue
		}
		if ip.PrivateIpAddress != nil {
			eni.Addresses = append(eni.Addresses, aws.ToString(ip.PrivateIpAddress))
		}
	}

	for _, prefix := range iface.Ipv4Prefixes {
		ips, e := ipPkg.PrefixToIps(aws.ToString(prefix.Ipv4Prefix), 0)
		if e != nil {
			err = fmt.Errorf("unable to parse CIDR %s: %w", aws.ToString(prefix.Ipv4Prefix), e)
			return
		}
		eni.Addresses = append(eni.Addresses, ips...)
		eni.Prefixes = append(eni.Prefixes, aws.ToString(prefix.Ipv4Prefix))
	}

	if iface.Association != nil && aws.ToString(iface.Association.PublicIp) != "" {
		eni.PublicIP = aws.ToString(iface.Association.PublicIp)
	}

	for _, g := range iface.Groups {
		if g.GroupId != nil {
			eni.SecurityGroups = append(eni.SecurityGroups, aws.ToString(g.GroupId))
		}
	}

	eni.Tags = make(map[string]string, len(iface.TagSet))
	for _, tag := range iface.TagSet {
		eni.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}

	return
}

// GetInstance returns the instance including its ENIs by the given instanceID
func (c *Client) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance := ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}

	var networkInterfaces []ec2_types.NetworkInterface
	var err error

	networkInterfaces, err = c.describeNetworkInterfacesByInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		ifId := *iface.NetworkInterfaceId
		_, eni, err := parseENI(&iface, vpcs, subnets, c.usePrimary)
		if err != nil {
			return nil, err
		}

		instance.Interfaces[ifId] = ipamTypes.InterfaceRevision{
			Resource: eni,
		}
	}
	return &instance, nil
}

// GetInstances returns the list of all instances including their ENIs as
// instanceMap
func (c *Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	var networkInterfaces []ec2_types.NetworkInterface
	var err error

	if len(c.instancesFilters) > 0 {
		networkInterfaces, err = c.describeNetworkInterfacesFromInstances(ctx)
	} else {
		networkInterfaces, err = c.describeNetworkInterfaces(ctx, subnets)
	}
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		id, eni, err := parseENI(&iface, vpcs, subnets, c.usePrimary)
		if err != nil {
			return nil, err
		}

		if id != "" {
			instances.Update(id, ipamTypes.InterfaceRevision{Resource: eni})
		}
	}

	return instances, nil
}

// describeVpcs lists the specific VPC based on the vpcID, or all VPCs if the vpcID is empty
func (c *Client) describeVpcs(ctx context.Context, vpcID string) ([]ec2_types.Vpc, error) {
	var result []ec2_types.Vpc
	input := &ec2.DescribeVpcsInput{}
	if vpcID != "" {
		input.VpcIds = []string{vpcID}
	}
	paginator := ec2.NewDescribeVpcsPaginator(c.ec2Client, input)
	for paginator.HasMorePages() {
		c.limiter.Limit(ctx, DescribeVpcs)
		sinceStart := spanstat.Start()
		output, err := paginator.NextPage(ctx)
		c.metricsAPI.ObserveAPICall(DescribeVpcs, deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}
		result = append(result, output.Vpcs...)
	}
	return result, nil
}

// GetVpcs retrieves and returns the VPC based on vpcID, or all VPCs if the vpcID is empty.
func (c *Client) GetVpcs(ctx context.Context, vpcID string) (ipamTypes.VirtualNetworkMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}

	vpcList, err := c.describeVpcs(ctx, vpcID)
	if err != nil {
		return nil, err
	}

	for _, v := range vpcList {
		vpc := &ipamTypes.VirtualNetwork{ID: aws.ToString(v.VpcId)}

		if v.CidrBlock != nil {
			vpc.PrimaryCIDR = aws.ToString(v.CidrBlock)
		}

		for _, c := range v.CidrBlockAssociationSet {
			if cidr := aws.ToString(c.CidrBlock); cidr != vpc.PrimaryCIDR {
				vpc.CIDRs = append(vpc.CIDRs, cidr)
			}
		}

		vpcs[vpc.ID] = vpc
	}

	return vpcs, nil
}

// describeSubnets lists the subnets in the vpcID, or all subnets if the vpcID is empty
func (c *Client) describeSubnets(ctx context.Context, vpcID string) ([]ec2_types.Subnet, error) {
	var result []ec2_types.Subnet
	input := &ec2.DescribeSubnetsInput{}
	if len(c.subnetsFilters) > 0 {
		input.Filters = c.subnetsFilters
	}
	input.Filters = addVPCFilterIfPresent(input.Filters, vpcID)
	paginator := ec2.NewDescribeSubnetsPaginator(c.ec2Client, input)
	for paginator.HasMorePages() {
		c.limiter.Limit(ctx, DescribeSubnets)
		sinceStart := spanstat.Start()
		output, err := paginator.NextPage(ctx)
		c.metricsAPI.ObserveAPICall(DescribeSubnets, deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}
		result = append(result, output.Subnets...)

	}
	return result, nil
}

// GetSubnets returns the subnets in the vpcID, or all subnets if the vpcID is empty.
func (c *Client) GetSubnets(ctx context.Context, vpcID string) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	subnetList, err := c.describeSubnets(ctx, vpcID)
	if err != nil {
		return nil, err
	}

	for _, s := range subnetList {
		cidr, err := netip.ParsePrefix(aws.ToString(s.CidrBlock))
		if err != nil {
			continue
		}

		subnet := &ipamTypes.Subnet{
			ID:                 aws.ToString(s.SubnetId),
			CIDR:               cidr,
			AvailableAddresses: int(aws.ToInt32(s.AvailableIpAddressCount)),
			Tags:               map[string]string{},
		}

		if s.AvailabilityZone != nil {
			subnet.AvailabilityZone = aws.ToString(s.AvailabilityZone)
		}

		if s.VpcId != nil {
			subnet.VirtualNetworkID = aws.ToString(s.VpcId)
		}

		for _, tag := range s.Tags {
			if aws.ToString(tag.Key) == "Name" {
				subnet.Name = aws.ToString(tag.Value)
			}
			subnet.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

// describeRouteTables lists the route tables in the vpcID, or all route tables if the vpcID is empty.
func (c *Client) describeRouteTables(ctx context.Context, vpcID string) ([]ec2_types.RouteTable, error) {
	var result []ec2_types.RouteTable
	input := &ec2.DescribeRouteTablesInput{}
	if len(c.routeTableFilters) > 0 {
		input.Filters = c.routeTableFilters
	}
	input.Filters = addVPCFilterIfPresent(input.Filters, vpcID)
	paginator := ec2.NewDescribeRouteTablesPaginator(c.ec2Client, input)
	for paginator.HasMorePages() {
		c.limiter.Limit(ctx, DescribeRouteTables)
		sinceStart := spanstat.Start()
		output, err := paginator.NextPage(ctx)
		c.metricsAPI.ObserveAPICall(DescribeRouteTables, deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}
		result = append(result, output.RouteTables...)
	}
	return result, nil
}

// GetRouteTables returns the route tables in the vpcID, or all route tables if the vpcID is empty.
func (c *Client) GetRouteTables(ctx context.Context, vpcID string) (ipamTypes.RouteTableMap, error) {
	routeTables := ipamTypes.RouteTableMap{}

	routeTableList, err := c.describeRouteTables(ctx, vpcID)
	if err != nil {
		return nil, err
	}

	for _, rt := range routeTableList {
		routeTable := &ipamTypes.RouteTable{
			ID:               aws.ToString(rt.RouteTableId),
			VirtualNetworkID: aws.ToString(rt.VpcId),
			Subnets:          map[string]struct{}{},
		}

		for _, association := range rt.Associations {
			if association.SubnetId != nil && association.AssociationState.State == ec2_types.RouteTableAssociationStateCodeAssociated {
				routeTable.Subnets[aws.ToString(association.SubnetId)] = struct{}{}
			}
		}

		routeTables[routeTable.ID] = routeTable
	}

	return routeTables, nil
}

// CreateNetworkInterface creates an ENI with the given parameters
func (c *Client) CreateNetworkInterface(ctx context.Context, toAllocate int32, subnetID, desc string, groups []string, allocatePrefixes bool) (string, *eniTypes.ENI, error) {

	input := &ec2.CreateNetworkInterfaceInput{
		Description: aws.String(desc),
		SubnetId:    aws.String(subnetID),
		Groups:      groups,
	}
	if allocatePrefixes {
		prefixCount := ipPkg.PrefixCeil(int(toAllocate), ipamOption.ENIPDBlockSizeIPv4)
		input.Ipv4PrefixCount = aws.Int32(int32(prefixCount))
		c.logger.Debug("Creating interface with prefixes",
			logfields.PrefixCount, prefixCount,
		)
	} else {
		input.SecondaryPrivateIpAddressCount = aws.Int32(toAllocate)
	}

	if len(c.eniTagSpecification.Tags) > 0 {
		input.TagSpecifications = []ec2_types.TagSpecification{
			c.eniTagSpecification,
		}
	}

	c.limiter.Limit(ctx, CreateNetworkInterface)
	sinceStart := spanstat.Start()
	output, err := c.ec2Client.CreateNetworkInterface(ctx, input)
	c.metricsAPI.ObserveAPICall(CreateNetworkInterface, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", nil, err
	}

	_, eni, err := parseENI(output.NetworkInterface, nil, nil, c.usePrimary)
	if err != nil {
		// The error is ignored on purpose. The allocation itself has
		// succeeded. The ability to parse and return the ENI
		// information is optional. Returning the ENI ID is sufficient
		// to allow for the caller to retrieve the ENI information via
		// the API or wait for a regular sync to fetch the information.
		return aws.ToString(output.NetworkInterface.NetworkInterfaceId), nil, nil
	}

	return eni.ID, eni, nil
}

// DeleteNetworkInterface deletes an ENI with the specified ID
func (c *Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	input := &ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(eniID),
	}

	c.limiter.Limit(ctx, DeleteNetworkInterface)
	sinceStart := spanstat.Start()
	_, err := c.ec2Client.DeleteNetworkInterface(ctx, input)
	c.metricsAPI.ObserveAPICall(DeleteNetworkInterface, deriveStatus(err), sinceStart.Seconds())
	return err
}

// AttachNetworkInterface attaches a previously created ENI to an instance
func (c *Client) AttachNetworkInterface(ctx context.Context, index int32, instanceID, eniID string) (string, error) {
	input := &ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        aws.Int32(index),
		InstanceId:         aws.String(instanceID),
		NetworkInterfaceId: aws.String(eniID),
		// NetworkCardIndex is the index of the physical network card on the instance (default is 0)
		//
		// While some instance types support multiple NICs, Cilium is only set up to use the primary NIC.
		// In the future, if multi-NIC support is introduced, this hard-coded value will need to be replaced by
		// a dynamic value.
		//
		// AWS is experiencing a bug in the validation of available device indexes when the network card index
		// is not set explicitly on instances supporting multiple network cards.
		// This workaround can be removed once AWS rolls out a fix, which is scheduled by January 30, 2026
		//
		// See https://github.com/cilium/cilium/pull/42512
		NetworkCardIndex: aws.Int32(0),
	}

	c.limiter.Limit(ctx, AttachNetworkInterface)
	sinceStart := spanstat.Start()
	output, err := c.ec2Client.AttachNetworkInterface(ctx, input)
	c.metricsAPI.ObserveAPICall(AttachNetworkInterface, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", err
	}

	return *output.AttachmentId, nil
}

// ModifyNetworkInterface modifies the attributes of an ENI
func (c *Client) ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error {
	changes := &ec2_types.NetworkInterfaceAttachmentChanges{
		AttachmentId:        aws.String(attachmentID),
		DeleteOnTermination: aws.Bool(deleteOnTermination),
	}

	input := &ec2.ModifyNetworkInterfaceAttributeInput{
		Attachment:         changes,
		NetworkInterfaceId: aws.String(eniID),
	}

	c.limiter.Limit(ctx, ModifyNetworkInterfaceAttribute)
	sinceStart := spanstat.Start()
	_, err := c.ec2Client.ModifyNetworkInterfaceAttribute(ctx, input)
	c.metricsAPI.ObserveAPICall(ModifyNetworkInterface, deriveStatus(err), sinceStart.Seconds())
	return err
}

// AssignPrivateIpAddresses assigns the specified number of secondary IP
// addresses
func (c *Client) AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int32) ([]string, error) {
	input := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             aws.String(eniID),
		SecondaryPrivateIpAddressCount: aws.Int32(addresses),
	}

	c.limiter.Limit(ctx, AssignPrivateIpAddresses)
	sinceStart := spanstat.Start()
	output, err := c.ec2Client.AssignPrivateIpAddresses(ctx, input)
	c.metricsAPI.ObserveAPICall(AssignPrivateIpAddresses, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}
	assignedIPs := make([]string, addresses)
	for i, ip := range output.AssignedPrivateIpAddresses {
		assignedIPs[i] = aws.ToString(ip.PrivateIpAddress)
	}
	return assignedIPs, nil
}

// UnassignPrivateIpAddresses unassigns specified IP addresses from ENI
func (c *Client) UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error {
	input := &ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: aws.String(eniID),
		PrivateIpAddresses: addresses,
	}

	c.limiter.Limit(ctx, UnassignPrivateIpAddresses)
	sinceStart := spanstat.Start()
	_, err := c.ec2Client.UnassignPrivateIpAddresses(ctx, input)
	c.metricsAPI.ObserveAPICall(UnassignPrivateIpAddresses, deriveStatus(err), sinceStart.Seconds())
	return err
}

func (c *Client) AssignENIPrefixes(ctx context.Context, eniID string, prefixes int32) error {
	input := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: aws.String(eniID),
		Ipv4PrefixCount:    aws.Int32(prefixes),
	}

	c.limiter.Limit(ctx, AssignPrivateIpAddresses)
	sinceStart := spanstat.Start()
	_, err := c.ec2Client.AssignPrivateIpAddresses(ctx, input)
	c.metricsAPI.ObserveAPICall(AssignPrivateIpAddresses, deriveStatus(err), sinceStart.Seconds())
	return err
}

func (c *Client) UnassignENIPrefixes(ctx context.Context, eniID string, prefixes []string) error {
	input := &ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: aws.String(eniID),
		Ipv4Prefixes:       prefixes,
	}

	c.limiter.Limit(ctx, UnassignPrivateIpAddresses)
	sinceStart := spanstat.Start()
	_, err := c.ec2Client.UnassignPrivateIpAddresses(ctx, input)
	c.metricsAPI.ObserveAPICall(UnassignPrivateIpAddresses, deriveStatus(err), sinceStart.Seconds())
	return err
}

// AssociateEIP tries to find an Elastic IP Address with the given tags and associates it with the given instance
func (c *Client) AssociateEIP(ctx context.Context, eniID string, eipTags ipamTypes.Tags) (string, error) {
	if len(eipTags) == 0 {
		return "", fmt.Errorf("no EIP tags were provided")
	}

	filters := make([]ec2_types.Filter, 0, len(eipTags))
	for k, v := range eipTags {
		filters = append(filters, ec2_types.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", k)),
			Values: []string{v},
		})
	}

	describeAddressesInput := &ec2.DescribeAddressesInput{
		Filters: filters,
	}
	c.limiter.Limit(ctx, DescribeAddresses)
	sinceStart := spanstat.Start()
	addresses, err := c.ec2Client.DescribeAddresses(ctx, describeAddressesInput)
	c.metricsAPI.ObserveAPICall(DescribeAddresses, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", err
	}
	c.logger.Info(
		"Found EIPs corresponding to tags",
		logfields.LenEIPS, len(addresses.Addresses),
		logfields.Tags, eipTags,
	)

	for _, address := range addresses.Addresses {
		// ignore EIPs that are already associated
		if address.AssociationId != nil {
			continue
		}
		associateAddressInput := &ec2.AssociateAddressInput{
			AllocationId:       address.AllocationId,
			AllowReassociation: aws.Bool(false),
			NetworkInterfaceId: aws.String(eniID),
		}
		c.limiter.Limit(ctx, AssociateAddress)
		sinceStart = spanstat.Start()
		association, err := c.ec2Client.AssociateAddress(ctx, associateAddressInput)
		c.metricsAPI.ObserveAPICall(AssociateAddress, deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return "", err
		}
		c.logger.Info(
			"Associated EIP successfully",
			logfields.EIP, aws.ToString(address.PublicIp),
			logfields.Interface, eniID,
			logfields.AssociationID, aws.ToString(association.AssociationId),
		)
		return aws.ToString(address.PublicIp), nil
	}

	return "", fmt.Errorf("no unassociated EIPs found for tags %v", eipTags)
}

func createAWSTagSlice(tags map[string]string) []ec2_types.Tag {
	awsTags := make([]ec2_types.Tag, 0, len(tags))
	for k, v := range tags {
		awsTag := ec2_types.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		awsTags = append(awsTags, awsTag)
	}

	return awsTags
}

// describeSecurityGroups lists the security groups in the vpcID, or all security groups if the vpcID is empty.
func (c *Client) describeSecurityGroups(ctx context.Context, vpcID string) ([]ec2_types.SecurityGroup, error) {
retry:
	for {
		var result []ec2_types.SecurityGroup
		input := &ec2.DescribeSecurityGroupsInput{}
		filters := addVPCFilterIfPresent([]ec2_types.Filter{}, vpcID)
		input.Filters = filters

		// Set MaxResults based on current configuration (nil means let AWS decide)
		input.MaxResults = c.getMaxResults()

		paginator := ec2.NewDescribeSecurityGroupsPaginator(c.ec2Client, input)
		for paginator.HasMorePages() {
			c.limiter.Limit(ctx, DescribeSecurityGroups)
			sinceStart := spanstat.Start()
			output, err := paginator.NextPage(ctx)
			c.metricsAPI.ObserveAPICall(DescribeSecurityGroups, deriveStatus(err), sinceStart.Seconds())
			if err != nil {
				// If OperationNotPermitted and we switch to pagination, retry the entire request
				if c.switchToPagination(err) {
					continue retry
				}
				return nil, err
			}
			result = append(result, output.SecurityGroups...)
		}

		return result, nil
	}
}

// GetSecurityGroups returns the security groups in the vpcID, or all security groups if the vpcID is empty.
func (c *Client) GetSecurityGroups(ctx context.Context, vpcID string) (types.SecurityGroupMap, error) {
	securityGroups := types.SecurityGroupMap{}

	secGroupList, err := c.describeSecurityGroups(ctx, vpcID)
	if err != nil {
		return securityGroups, err
	}

	for _, secGroup := range secGroupList {
		id := aws.ToString(secGroup.GroupId)

		securityGroup := &types.SecurityGroup{
			ID:    id,
			VpcID: aws.ToString(secGroup.VpcId),
			Tags:  map[string]string{},
		}
		for _, tag := range secGroup.Tags {
			key := aws.ToString(tag.Key)
			value := aws.ToString(tag.Value)
			securityGroup.Tags[key] = value
		}

		securityGroups[id] = securityGroup
	}

	return securityGroups, nil
}

// GetInstanceTypes returns all the known EC2 instance types in the configured region
func (c *Client) GetInstanceTypes(ctx context.Context) ([]ec2_types.InstanceTypeInfo, error) {
	var result []ec2_types.InstanceTypeInfo
	paginator := ec2.NewDescribeInstanceTypesPaginator(c.ec2Client, &ec2.DescribeInstanceTypesInput{})
	for paginator.HasMorePages() {
		c.limiter.Limit(ctx, DescribeInstanceTypes)
		sinceStart := spanstat.Start()
		output, err := paginator.NextPage(ctx)
		c.metricsAPI.ObserveAPICall(DescribeInstanceTypes, deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}
		result = append(result, output.InstanceTypes...)
	}
	return result, nil
}

// addVPCFilterIfPresent checks if a vpcID is provided and, if so, adds a
// vpc-id filter to the given list of filters.
func addVPCFilterIfPresent(filters []ec2_types.Filter, vpcID string) []ec2_types.Filter {
	if vpcID == "" {
		return filters
	}
	return append(filters, ec2_types.Filter{
		Name:   aws.String("vpc-id"),
		Values: []string{vpcID},
	})
}
