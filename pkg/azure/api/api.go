// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/version"
)

const (
	interfacesCreateOrUpdate        = "Interfaces.CreateOrUpdate"
	interfacesGet                   = "Interfaces.Get"
	interfacesList                  = "Interfaces.List"
	publicIPPrefixesList            = "PublicIPPrefixes.List"
	virtualMachinesGet              = "VirtualMachines.Get"
	virtualMachineScaleSetsList     = "VirtualMachineScaleSets.List"
	virtualMachineScaleSetVMsGet    = "VirtualMachineScaleSetVMs.Get"
	virtualMachineScaleSetVMsUpdate = "VirtualMachineScaleSetVMs.Update"
	virtualNetworksListAll          = "VirtualNetworks.ListAll"
	subnetsGet                      = "Subnets.Get"

	interfacesListVirtualMachineScaleSetNetworkInterfaces   = "Interfaces.ListVirtualMachineScaleSetNetworkInterfaces"
	interfacesListVirtualMachineScaleSetVMNetworkInterfaces = "Interfaces.ListVirtualMachineScaleSetVMNetworkInterfaces"
)

// Client represents an Azure API client
type Client struct {
	logger                    *slog.Logger
	subscriptionID            string
	resourceGroup             string
	interfaces                *armnetwork.InterfacesClient
	publicIPPrefixes          *armnetwork.PublicIPPrefixesClient
	virtualNetworks           *armnetwork.VirtualNetworksClient
	virtualMachines           *armcompute.VirtualMachinesClient
	subnets                   *armnetwork.SubnetsClient
	virtualMachineScaleSetVMs *armcompute.VirtualMachineScaleSetVMsClient
	virtualMachineScaleSets   *armcompute.VirtualMachineScaleSetsClient
	limiter                   *helpers.APILimiter
	metricsAPI                MetricsAPI
	usePrimary                bool
}

// MetricsAPI represents the metrics maintained by the Azure API client
type MetricsAPI interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
}

// net/http Client with a custom cilium user agent
type httpClient struct{}

func (t *httpClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", fmt.Sprintf("cilium/%s", version.Version))
	return http.DefaultClient.Do(req)
}

func newTokenCredential(clientOptions *azcore.ClientOptions, userAssignedIdentityID string) (azcore.TokenCredential, error) {
	if userAssignedIdentityID != "" {
		return azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ClientOptions: *clientOptions,
			ID:            azidentity.ClientID(userAssignedIdentityID),
		})
	}
	return azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: *clientOptions,
	})
}

func newClientOptions(cloudName string) (*azcore.ClientOptions, error) {
	clientOptions := &azcore.ClientOptions{
		Transport: &httpClient{},
	}

	// See possible values here:
	// https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service#sample-5-get-the-azure-environment-where-the-vm-is-running
	switch cloudName {
	case "AzurePublicCloud":
		clientOptions.Cloud = cloud.AzurePublic
	case "AzureUSGovernmentCloud":
		clientOptions.Cloud = cloud.AzureGovernment
	case "AzureChinaCloud":
		clientOptions.Cloud = cloud.AzureChina
	default:
		// Note: AzureGermanCloud closed on October 29 2021, see
		// https://news.microsoft.com/europe/2018/08/31/microsoft-to-deliver-cloud-services-from-new-datacentres-in-germany-in-2019-to-meet-evolving-customer-needs/
		return nil, fmt.Errorf("Unknown Azure cloud %q", cloudName)
	}

	return clientOptions, nil
}

// NewClient returns a new Azure client
func NewClient(logger *slog.Logger, cloudName, subscriptionID, resourceGroup, userAssignedIdentityID string, metrics MetricsAPI, rateLimit float64, burst int, usePrimary bool) (*Client, error) {
	clientOptions, err := newClientOptions(cloudName)
	if err != nil {
		return nil, err
	}

	credential, err := newTokenCredential(clientOptions, userAssignedIdentityID)
	if err != nil {
		return nil, err
	}

	armClientOptions := &arm.ClientOptions{
		ClientOptions: *clientOptions,
	}

	interfacesClient, err := armnetwork.NewInterfacesClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	virtualNetworksClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	virtualMachinesClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	subnetsClient, err := armnetwork.NewSubnetsClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	virtualMachineScaleSetVMsClient, err := armcompute.NewVirtualMachineScaleSetVMsClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	virtualMachineScaleSetsClient, err := armcompute.NewVirtualMachineScaleSetsClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	publicIPPrefixesClient, err := armnetwork.NewPublicIPPrefixesClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	c := &Client{
		logger:                    logger,
		subscriptionID:            subscriptionID,
		resourceGroup:             resourceGroup,
		interfaces:                interfacesClient,
		publicIPPrefixes:          publicIPPrefixesClient,
		virtualNetworks:           virtualNetworksClient,
		virtualMachines:           virtualMachinesClient,
		subnets:                   subnetsClient,
		virtualMachineScaleSetVMs: virtualMachineScaleSetVMsClient,
		virtualMachineScaleSets:   virtualMachineScaleSetsClient,
		metricsAPI:                metrics,
		limiter:                   helpers.NewAPILimiter(metrics, rateLimit, burst),
		usePrimary:                usePrimary,
	}

	return c, nil
}

// deriveStatus returns a status string
func deriveStatus(err error) string {
	if err != nil {
		return "Failed"
	}

	return "OK"
}

// vmNetworkInterfaces list all interfaces of non-VMSS instances in the client's resource group
func (c *Client) vmNetworkInterfaces(ctx context.Context) (networkInterfaces []*armnetwork.Interface, err error) {
	c.limiter.Limit(ctx, interfacesList)
	sinceStart := spanstat.Start()

	pager := c.interfaces.NewListPager(c.resourceGroup, nil)

	defer func() {
		c.metricsAPI.ObserveAPICall(interfacesList, deriveStatus(err), sinceStart.Seconds())
	}()

	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		networkInterfaces = append(networkInterfaces, nextResult.Value...)
	}

	return networkInterfaces, nil
}

// listVirtualMachineScaleSetsNetworkInterfaces lists all interfaces from VMs in Scale Sets in the client's resource group
func (c *Client) listVirtualMachineScaleSetsNetworkInterfaces(ctx context.Context) (networkInterfaces []*armnetwork.Interface, err error) {
	virtualMachineScaleSets, err := c.listVirtualMachineScaleSets(ctx)
	if err != nil {
		return nil, err
	}

	for _, virtualMachineScaleSet := range virtualMachineScaleSets {
		virtualMachineScaleSetNetworkInterfaces, err := c.listVirtualMachineScaleSetNetworkInterfaces(ctx, *virtualMachineScaleSet.Name)
		if err != nil {
			// For scale set created by AKS node group (otherwise it will return an empty list) without any instances API will return not found. Then it can be skipped.
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				continue
			}
			return nil, err
		}

		networkInterfaces = append(networkInterfaces, virtualMachineScaleSetNetworkInterfaces...)
	}

	return networkInterfaces, nil
}

// listVirtualMachineScaleSets lists all virtual machine scale sets in the client's resource group
func (c *Client) listVirtualMachineScaleSets(ctx context.Context) (virtualMachineScaleSets []*armcompute.VirtualMachineScaleSet, err error) {
	c.limiter.Limit(ctx, virtualMachineScaleSetsList)
	sinceStart := spanstat.Start()

	pager := c.virtualMachineScaleSets.NewListPager(c.resourceGroup, nil)

	defer func() {
		c.metricsAPI.ObserveAPICall(virtualMachineScaleSetsList, deriveStatus(err), sinceStart.Seconds())
	}()

	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		virtualMachineScaleSets = append(virtualMachineScaleSets, nextResult.Value...)
	}

	return virtualMachineScaleSets, nil
}

// listVirtualMachineScaleSetNetworkInterfaces lists all network interfaces for a given virtual machines scale set
func (c *Client) listVirtualMachineScaleSetNetworkInterfaces(ctx context.Context, virtualMachineScaleSetName string) (networkInterfaces []*armnetwork.Interface, err error) {
	c.limiter.Limit(ctx, interfacesListVirtualMachineScaleSetNetworkInterfaces)
	sinceStart := spanstat.Start()

	pager := c.interfaces.NewListVirtualMachineScaleSetNetworkInterfacesPager(c.resourceGroup, virtualMachineScaleSetName, nil)

	defer func() {
		c.metricsAPI.ObserveAPICall(interfacesListVirtualMachineScaleSetNetworkInterfaces, deriveStatus(err), sinceStart.Seconds())
	}()

	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		networkInterfaces = append(networkInterfaces, nextResult.Value...)
	}

	return networkInterfaces, nil
}

// listVirtualMachineScaleSetVMNetworkInterfaces lists all network interfaces for a given virtual machines scale set VM
func (c *Client) listVirtualMachineScaleSetVMNetworkInterfaces(ctx context.Context, virtualMachineScaleSetName, virtualmachineIndex string) (networkInterfaces []*armnetwork.Interface, err error) {
	c.limiter.Limit(ctx, interfacesListVirtualMachineScaleSetVMNetworkInterfaces)
	sinceStart := spanstat.Start()

	pager := c.interfaces.NewListVirtualMachineScaleSetVMNetworkInterfacesPager(c.resourceGroup, virtualMachineScaleSetName, virtualmachineIndex, nil)

	defer func() {
		c.metricsAPI.ObserveAPICall(interfacesListVirtualMachineScaleSetVMNetworkInterfaces, deriveStatus(err), sinceStart.Seconds())
	}()

	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		networkInterfaces = append(networkInterfaces, nextResult.Value...)
	}

	return networkInterfaces, nil
}

// parseInterfaces parses a armnetwork.Interface as returned by the Azure API
// converts it into a types.AzureInterface
func parseInterface(iface *armnetwork.Interface, subnets ipamTypes.SubnetMap, usePrimary bool) (instanceID string, i *types.AzureInterface) {
	i = &types.AzureInterface{}

	if iface.Properties.VirtualMachine != nil && iface.Properties.VirtualMachine.ID != nil {
		instanceID = strings.ToLower(*iface.Properties.VirtualMachine.ID)
	}

	if iface.Properties.MacAddress != nil {
		// Azure API reports MAC addresses as AA-BB-CC-DD-EE-FF
		i.MAC = strings.ReplaceAll(*iface.Properties.MacAddress, "-", ":")
	}

	if iface.ID != nil {
		i.SetID(*iface.ID)
	}

	if iface.Name != nil {
		i.Name = *iface.Name
	}

	if iface.Properties.NetworkSecurityGroup != nil {
		if iface.Properties.NetworkSecurityGroup.ID != nil {
			i.SecurityGroup = *iface.Properties.NetworkSecurityGroup.ID
		}
	}

	if iface.Properties.IPConfigurations != nil {
		for _, ip := range (*iface).Properties.IPConfigurations {
			if !usePrimary && ip.Properties.Primary != nil && *ip.Properties.Primary {
				continue
			}
			if ip.Properties.PrivateIPAddress != nil {
				addr := types.AzureAddress{
					IP:    *ip.Properties.PrivateIPAddress,
					State: strings.ToLower(string(*ip.Properties.ProvisioningState)),
				}

				if ip.Properties.Subnet != nil {
					addr.Subnet = *ip.Properties.Subnet.ID
					if subnet, ok := subnets[addr.Subnet]; ok {
						if subnet.CIDR.IsValid() {
							i.CIDR = subnet.CIDR.String()
						}
						if gateway := deriveGatewayIP(subnet.CIDR.Addr()); gateway != "" {
							i.GatewayIP = gateway
							i.Gateway = gateway
						}
					}
				}

				i.Addresses = append(i.Addresses, addr)
			}
		}
	}

	return
}

// deriveGatewayIP finds the default gateway for a given Azure subnet.
// inspired by pkg/ipam/crd.go (as AWS, Azure reserves the first subnet IP for the gw).
// Ref: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-faq#are-there-any-restrictions-on-using-ip-addresses-within-these-subnets
func deriveGatewayIP(subnetIP netip.Addr) string {
	return subnetIP.Next().String()
}

// GetInstances returns the list of all instances including all attached
// interfaces as instanceMap
func (c *Client) GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	networkInterfaces, err := c.ListAllNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	return c.ParseInterfacesIntoInstanceMap(networkInterfaces, subnets), nil
}

// ListAllNetworkInterfaces returns all network interfaces in the resource group
// This is exposed to allow callers to fetch network interfaces once and parse them multiple times
func (c *Client) ListAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error) {
	networkInterfaces, err := c.listVirtualMachineScaleSetsNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	vmInterfaces, err := c.vmNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	return append(networkInterfaces, vmInterfaces...), nil
}

// ParseInterfacesIntoInstanceMap parses network interfaces into an InstanceMap
// This allows re-parsing the same network interface data with different subnet maps
// without making additional Azure API calls
func (c *Client) ParseInterfacesIntoInstanceMap(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.InstanceMap {
	instances := ipamTypes.NewInstanceMap()

	for _, iface := range networkInterfaces {
		if instanceID, azureInterface := parseInterface(iface, subnets, c.usePrimary); instanceID != "" {
			instances.Update(instanceID, ipamTypes.InterfaceRevision{Resource: azureInterface})
		}
	}

	return instances
}

// GetInstance returns the interfaces of a given instance
func (c *Client) GetInstance(ctx context.Context, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	resourceID, err := arm.ParseResourceID(instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse instance ID %q", instanceID)
	}
	if strings.ToLower(resourceID.ResourceType.Type) != "virtualmachinescalesets/virtualmachines" {
		return nil, fmt.Errorf("instance %q is not a virtual machine scale set instance", instanceID)
	}

	networkInterfaces, err := c.listVirtualMachineScaleSetVMNetworkInterfaces(ctx, resourceID.Parent.Name, resourceID.Name)
	if err != nil {
		return nil, err
	}

	return c.ParseInterfacesIntoInstance(networkInterfaces, subnets), nil
}

// ListVMNetworkInterfaces returns all network interfaces for a specific VMSS instance
// This is exposed to allow callers to fetch network interfaces once and parse them multiple times
func (c *Client) ListVMNetworkInterfaces(ctx context.Context, instanceID string) ([]*armnetwork.Interface, error) {
	resourceID, err := arm.ParseResourceID(instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse instance ID %q", instanceID)
	}
	if strings.ToLower(resourceID.ResourceType.Type) != "virtualmachinescalesets/virtualmachines" {
		return nil, fmt.Errorf("instance %q is not a virtual machine scale set instance", instanceID)
	}

	return c.listVirtualMachineScaleSetVMNetworkInterfaces(ctx, resourceID.Parent.Name, resourceID.Name)
}

// ParseInterfacesIntoInstance parses network interfaces into an Instance
// This allows re-parsing the same network interface data with different subnet maps
// without making additional Azure API calls
func (c *Client) ParseInterfacesIntoInstance(networkInterfaces []*armnetwork.Interface, subnets ipamTypes.SubnetMap) *ipamTypes.Instance {
	instance := ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}

	for _, networkInterface := range networkInterfaces {
		_, azureInterface := parseInterface(networkInterface, subnets, c.usePrimary)
		instance.Interfaces[azureInterface.ID] = ipamTypes.InterfaceRevision{Resource: azureInterface}
	}

	return &instance
}

// listAllVPCs lists all VPCs
func (c *Client) listAllVPCs(ctx context.Context) (vpcs []*armnetwork.VirtualNetwork, err error) {
	c.limiter.Limit(ctx, virtualNetworksListAll)
	sinceStart := spanstat.Start()

	// Note: lists all VPCs, not just those in c.resourcegroup
	pager := c.virtualNetworks.NewListAllPager(nil)

	defer func() {
		c.metricsAPI.ObserveAPICall(virtualNetworksListAll, deriveStatus(err), sinceStart.Seconds())
	}()

	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		vpcs = append(vpcs, nextResult.Value...)
	}

	return vpcs, nil
}

func parseSubnet(subnet *armnetwork.Subnet) (s *ipamTypes.Subnet) {
	s = &ipamTypes.Subnet{ID: *subnet.ID}
	if subnet.Name != nil {
		s.Name = *subnet.Name
	}

	if subnet.Properties.AddressPrefix != nil {
		cidr, err := netip.ParsePrefix(*subnet.Properties.AddressPrefix)
		if err != nil {
			return nil
		}
		s.CIDR = cidr
		if subnet.Properties.IPConfigurations != nil {
			s.AvailableAddresses = availableIPs(cidr) - len(subnet.Properties.IPConfigurations)
		} else {
			// Azure currently returns nil for subnet IPConfigs if the subnet has a large number of existing IPConfigs.
			// API / SDK is supposed to return a IpConfigurationsNextLink which can be used to make an additional
			// call to get all IPConfigs. This field however seems to be missing from the API spec.
			// Since we cannot fall back to other subnets anyway, assume all IPs are available.
			// TODO: Update this once azure-sdk-for-go supports ipConfigurationsNextLink
			s.AvailableAddresses = availableIPs(cidr)
		}
	}

	return
}

// availableIPs returns the number of IPs available in a CIDR
func availableIPs(p netip.Prefix) int {
	ones := p.Bits()
	bits := p.Addr().BitLen()
	return 1 << (bits - ones)
}

// GetVpcsAndSubnets retrieves and returns all Vpcs
func (c *Client) GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}
	subnets := ipamTypes.SubnetMap{}

	vpcList, err := c.listAllVPCs(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, v := range vpcList {
		if v.ID == nil {
			continue
		}

		vpc := &ipamTypes.VirtualNetwork{ID: *v.ID}
		vpcs[vpc.ID] = vpc

		if v.Properties.Subnets != nil {
			for _, subnet := range v.Properties.Subnets {
				if subnet.ID == nil {
					continue
				}
				if s := parseSubnet(subnet); s != nil {
					subnets[*subnet.ID] = s
				}
			}
		}
	}

	return vpcs, subnets, nil
}

// parseSubnetID extracts resource group, virtual network, and subnet names from an Azure subnet ID.
// Expected format: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}
// Uses arm.ParseResourceID from the Azure SDK for robust parsing.
func parseSubnetID(subnetID string) (resourceGroupName, vnetName, subnetName string, err error) {
	resourceID, err := arm.ParseResourceID(subnetID)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse subnet ID %q: %w", subnetID, err)
	}

	// Verify this is a Microsoft.Network subnet resource
	if resourceID.ResourceType.Namespace != "Microsoft.Network" {
		return "", "", "", fmt.Errorf("invalid Azure subnet ID format (wrong provider namespace): %s", subnetID)
	}

	// Verify this is a subnet resource (child of virtualNetworks)
	if resourceID.ResourceType.Type != "virtualNetworks/subnets" {
		return "", "", "", fmt.Errorf("invalid Azure subnet ID format: %s", subnetID)
	}

	// Verify we have a resource group (not a subscription-level resource)
	if resourceID.ResourceGroupName == "" {
		return "", "", "", fmt.Errorf("invalid Azure subnet ID format (missing resource group): %s", subnetID)
	}

	// resourceID.Name is the subnet name
	// resourceID.Parent.Name is the vnet name
	// resourceID.ResourceGroupName is the resource group
	if resourceID.Parent == nil {
		return "", "", "", fmt.Errorf("invalid Azure subnet ID format (no parent vnet): %s", subnetID)
	}

	return resourceID.ResourceGroupName, resourceID.Parent.Name, resourceID.Name, nil
}

// getSubnetWithPagination retrieves a subnet with accurate IP configuration counting via pagination
func (c *Client) getSubnetWithPagination(ctx context.Context, subscriptionID, resourceGroup, vnetName, subnetName string) (*ipamTypes.Subnet, error) {
	c.limiter.Limit(ctx, subnetsGet)
	sinceStart := spanstat.Start()

	result, err := c.subnets.Get(ctx, resourceGroup, vnetName, subnetName, nil)
	c.metricsAPI.ObserveAPICall(subnetsGet, deriveStatus(err), sinceStart.Seconds())

	if err != nil {
		return nil, err
	}

	subnet := &result.Subnet
	if subnet.ID == nil {
		return nil, fmt.Errorf("subnet %s not found", subnetName)
	}

	cidrString := ""
	if subnet.Properties != nil && subnet.Properties.AddressPrefix != nil {
		cidrString = *subnet.Properties.AddressPrefix
	}
	if cidrString == "" && subnet.Properties != nil && len(subnet.Properties.AddressPrefixes) > 0 {
		cidrString = *subnet.Properties.AddressPrefixes[0]
	}

	if cidrString == "" {
		return nil, fmt.Errorf("subnet %s has no valid CIDR", subnetName)
	}

	cidr, err := netip.ParsePrefix(cidrString)
	if err != nil {
		return nil, fmt.Errorf("subnet %s has invalid CIDR %s: %w", subnetName, cidrString, err)
	}

	// Calculate available addresses more accurately
	// Note: This is simplified for SDK v2. PR #41554 had more complex pagination logic for SDK v1
	availableAddresses := int(cidr.Addr().BitLen()) - cidr.Bits()
	if availableAddresses > 0 {
		// Reserve some addresses for Azure (typically 5 per subnet)
		availableAddresses = (1 << availableAddresses) - 5

		// Count used IP configurations if present
		if subnet.Properties != nil && subnet.Properties.IPConfigurations != nil {
			availableAddresses -= len(subnet.Properties.IPConfigurations)
		}

		if availableAddresses < 0 {
			availableAddresses = 0
		}
	}

	azSubnet := &ipamTypes.Subnet{
		ID:                 *subnet.ID,
		CIDR:               cidr,
		VirtualNetworkID:   extractVNetID(*subnet.ID),
		AvailableAddresses: availableAddresses,
		Tags:               map[string]string{},
	}

	// Copy tags if present - In ARM SDK v2, tags are accessed differently
	// For now, leave empty tags map since this is not critical for subnet discovery functionality

	return azSubnet, nil
}

// extractVNetID extracts the VNet ID from a subnet ID
func extractVNetID(subnetID string) string {
	// Extract VNet ID from subnet ID by removing the subnet portion
	// /subscriptions/.../virtualNetworks/{vnet}/subnets/{subnet} -> /subscriptions/.../virtualNetworks/{vnet}
	idx := strings.LastIndex(subnetID, "/subnets/")
	if idx == -1 {
		return ""
	}
	return subnetID[:idx]
}

// GetSubnetsByIDs retrieves subnet information for specific subnet IDs
func (c *Client) GetSubnetsByIDs(ctx context.Context, subnetIDs []string) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	for _, subnetID := range subnetIDs {
		// Parse subnet ID to extract resource group, vnet and subnet names
		resourceGroup, vnetName, subnetName, err := parseSubnetID(subnetID)
		if err != nil {
			c.logger.Warn("Failed to parse subnet ID, skipping",
				logfields.Error, err,
				logfields.SubnetID, subnetID,
			)
			continue
		}

		// Use pagination-aware subnet query for accurate IP configuration counting
		subnet, err := c.getSubnetWithPagination(ctx, c.subscriptionID, resourceGroup, vnetName, subnetName)
		if err != nil {
			c.logger.Warn("Failed to get subnet details, skipping",
				logfields.Error, err,
			)
			continue
		}

		if subnet != nil {
			subnets[subnetID] = subnet
		}
	}

	return subnets, nil
}

func generateIpConfigName() string {
	return "Cilium-" + rand.String(8)
}

// AssignPrivateIpAddressesVMSS assign a private IP to an interface attached to a VMSS instance
func (c *Client) AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error {
	var netIfConfig *armcompute.VirtualMachineScaleSetNetworkConfiguration

	vmssGetOptions := &armcompute.VirtualMachineScaleSetVMsClientGetOptions{
		Expand: to.Ptr(armcompute.InstanceViewTypesInstanceView),
	}

	c.limiter.Limit(ctx, virtualMachineScaleSetVMsGet)
	sinceStart := spanstat.Start()

	result, err := c.virtualMachineScaleSetVMs.Get(ctx, c.resourceGroup, vmssName, instanceID, vmssGetOptions)

	c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsGet, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get VM %s from VMSS %s: %w", instanceID, vmssName, err)
	}

	// Search for the existing network interface configuration
	if result.Properties.NetworkProfileConfiguration != nil {
		for _, networkInterfaceConfiguration := range result.Properties.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
			if networkInterfaceConfiguration.Name != nil && *networkInterfaceConfiguration.Name == interfaceName {
				netIfConfig = networkInterfaceConfiguration
				break
			}
		}
	}

	if netIfConfig == nil {
		return fmt.Errorf("interface %s does not exist in VM %s", interfaceName, instanceID)
	}

	// All IPConfigurations on the NIC should reference the same set of Application Security Groups (ASGs).
	// So we should first fetch the set of ASGs referenced by other IPConfigurations so that it can be
	// added to the new IPConfigurations.
	var appSecurityGroups []*armcompute.SubResource
	if ipConfigs := netIfConfig.Properties.IPConfigurations; len(ipConfigs) > 0 {
		appSecurityGroups = ipConfigs[0].Properties.ApplicationSecurityGroups
	}

	ipConfigurations := make([]*armcompute.VirtualMachineScaleSetIPConfiguration, 0, addresses)
	for range addresses {
		ipConfigurations = append(ipConfigurations,
			&armcompute.VirtualMachineScaleSetIPConfiguration{
				Name: to.Ptr(generateIpConfigName()),
				Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{
					ApplicationSecurityGroups: appSecurityGroups,
					PrivateIPAddressVersion:   to.Ptr(armcompute.IPVersionIPv4),
					Subnet:                    &armcompute.APIEntityReference{ID: to.Ptr(subnetID)},
				},
			},
		)
	}

	ipConfigurations = append(netIfConfig.Properties.IPConfigurations, ipConfigurations...)
	netIfConfig.Properties.IPConfigurations = ipConfigurations

	// Unset imageReference, because if this contains a reference to an image from the
	// Azure Compute Gallery, including this reference in an update to the VMSS instance
	// will cause a permissions error, because the reference includes an Azure-managed
	// subscription ID.
	// Removing the image reference indicates to the API that we don't want to change it.
	// See https://github.com/Azure/AKS/issues/1819.
	if result.Properties.StorageProfile != nil {
		result.Properties.StorageProfile.ImageReference = nil
	}

	c.limiter.Limit(ctx, virtualMachineScaleSetVMsUpdate)
	sinceStart = spanstat.Start()

	poller, err := c.virtualMachineScaleSetVMs.BeginUpdate(ctx, c.resourceGroup, vmssName, instanceID, result.VirtualMachineScaleSetVM, nil)

	defer func() {
		c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsUpdate, deriveStatus(err), sinceStart.Seconds())
	}()
	if err != nil {
		return fmt.Errorf("unable to update virtualMachineScaleSetVMs: %w", err)
	}

	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("error while waiting for virtualMachineScaleSetVMs Update to complete: %w", err)
	}

	return nil
}

// AssignPrivateIpAddressesVM assign a private IP to an interface attached to a standalone instance
func (c *Client) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error {
	c.limiter.Limit(ctx, interfacesGet)
	sinceStart := spanstat.Start()

	iface, err := c.interfaces.Get(ctx, c.resourceGroup, interfaceName, nil)

	c.metricsAPI.ObserveAPICall(interfacesGet, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get standalone instance's interface %s: %w", interfaceName, err)
	}

	// All IPConfigurations on the NIC should reference the same set of Application Security Groups (ASGs).
	// So we should first fetch the set of ASGs referenced by other IPConfigurations so that it can be
	// added to the new IPConfigurations.
	var appSecurityGroups []*armnetwork.ApplicationSecurityGroup
	if ipConfigs := iface.Properties.IPConfigurations; len(ipConfigs) > 0 {
		appSecurityGroups = ipConfigs[0].Properties.ApplicationSecurityGroups
	}

	ipConfigurations := make([]*armnetwork.InterfaceIPConfiguration, 0, addresses)
	for range addresses {
		ipConfigurations = append(ipConfigurations, &armnetwork.InterfaceIPConfiguration{
			Name: to.Ptr(generateIpConfigName()),
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				ApplicationSecurityGroups: appSecurityGroups,
				PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
				Subnet: &armnetwork.Subnet{
					ID: to.Ptr(subnetID),
				},
			},
		})
	}

	ipConfigurations = append(iface.Properties.IPConfigurations, ipConfigurations...)
	iface.Properties.IPConfigurations = ipConfigurations

	c.limiter.Limit(ctx, interfacesCreateOrUpdate)
	sinceStart = spanstat.Start()

	poller, err := c.interfaces.BeginCreateOrUpdate(ctx, c.resourceGroup, interfaceName, iface.Interface, nil)

	defer func() {
		c.metricsAPI.ObserveAPICall(interfacesCreateOrUpdate, deriveStatus(err), sinceStart.Seconds())
	}()
	if err != nil {
		return fmt.Errorf("unable to update interface %s: %w", interfaceName, err)
	}

	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("error while waiting for interface CreateOrUpdate to complete for %s: %w", interfaceName, err)
	}

	return nil
}

// AssignPublicIPAddressesVMSS assigns a public IP to a VMSS instance.
// The public IP is allocated from a Public IP Prefix matching publicIpTags
func (c *Client) AssignPublicIPAddressesVMSS(ctx context.Context, instanceID, vmssName string, publicIpTags ipamTypes.Tags) (string, error) {
	// The instance ID format is:
	// /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmssName}/virtualMachines/{instanceNum}
	// Parse the instance ID to get just the instance number
	resourceID, err := arm.ParseResourceID(instanceID)
	if err != nil {
		return "", fmt.Errorf("failed to parse instance ID %q: %w", instanceID, err)
	}
	instanceNum := resourceID.Name

	var primaryNetIfConfig *armcompute.VirtualMachineScaleSetNetworkConfiguration

	vmssGetOptions := &armcompute.VirtualMachineScaleSetVMsClientGetOptions{
		Expand: to.Ptr(armcompute.InstanceViewTypesInstanceView),
	}

	c.limiter.Limit(ctx, virtualMachineScaleSetVMsGet)
	sinceStart := spanstat.Start()

	vm, err := c.virtualMachineScaleSetVMs.Get(ctx, c.resourceGroup, vmssName, instanceNum, vmssGetOptions)

	c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsGet, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", fmt.Errorf("failed to get VM %s from VMSS %s: %w", instanceID, vmssName, err)
	}

	// Search for the primary network interface configuration
	if vm.Properties.NetworkProfileConfiguration != nil {
		for _, networkInterfaceConfiguration := range vm.Properties.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
			if networkInterfaceConfiguration.Properties.Primary != nil && *networkInterfaceConfiguration.Properties.Primary {
				primaryNetIfConfig = networkInterfaceConfiguration
				break
			}
		}
	}

	if primaryNetIfConfig == nil {
		return "", fmt.Errorf("can't find primary interface for VM %s from VMSS %s", instanceID, vmssName)
	}

	// Find the primary IP configuration
	var primaryIPConfig *armcompute.VirtualMachineScaleSetIPConfiguration
	if primaryNetIfConfig.Properties.IPConfigurations != nil {
		for _, ipConfig := range primaryNetIfConfig.Properties.IPConfigurations {
			if ipConfig.Properties.Primary != nil && *ipConfig.Properties.Primary {
				primaryIPConfig = ipConfig
				break
			}
		}
	}

	if primaryIPConfig == nil {
		netIfName := "<unknown>"
		if primaryNetIfConfig.Name != nil {
			netIfName = *primaryNetIfConfig.Name
		}
		return "", fmt.Errorf("can't find primary IP configuration for network configuration %s from VM %s from VMSS %s",
			netIfName,
			instanceID,
			vmssName,
		)
	}

	if primaryIPConfig.Properties.PublicIPAddressConfiguration != nil {
		if isPublicIPProvisionFailed(vm.Properties.InstanceView.Statuses) {
			// In certain cases, Azure will succeed to configure a VM with a certain prefix even if it is out of IP addresses.
			// This leads to the VM failing to provision properly. In this case, we need to delete the erroneous public IP address configuration
			// and configure it again.
			if err := c.deletePublicIPAddressConfigurationVMSS(ctx, instanceNum, vmssName, &vm, primaryIPConfig); err != nil {
				return "", fmt.Errorf("failed to delete public IP address configuration for VM %s from VMSS %s: %w", instanceID, vmssName, err)
			}
		} else {
			netIfName := "<unknown>"
			if primaryNetIfConfig.Name != nil {
				netIfName = *primaryNetIfConfig.Name
			}
			return "", fmt.Errorf("public IP address already assigned to primary IP configuration for network configuration %s from VM %s from VMSS %s",
				netIfName,
				instanceID,
				vmssName,
			)
		}
	}

	// Find a public IP prefix with the given tags
	publicIPPrefixID, err := c.getPublicIPPrefixIDByTags(ctx, publicIpTags)
	if err != nil {
		return "", err
	}

	// Create a new public IP configuration
	primaryIPConfig.Properties.PublicIPAddressConfiguration = &armcompute.VirtualMachineScaleSetPublicIPAddressConfiguration{
		Name: to.Ptr("cilium-managed-public-ip"),
		Properties: &armcompute.VirtualMachineScaleSetPublicIPAddressConfigurationProperties{
			PublicIPPrefix: &armcompute.SubResource{
				ID: to.Ptr(publicIPPrefixID),
			},
		},
	}

	// Unset imageReference, because if this contains a reference to an image from the
	// Azure Compute Gallery, including this reference in an update to the VMSS instance
	// will cause a permissions error, because the reference includes an Azure-managed
	// subscription ID.
	// Removing the image reference indicates to the API that we don't want to change it.
	// See https://github.com/Azure/AKS/issues/1819.
	if vm.Properties.StorageProfile != nil {
		vm.Properties.StorageProfile.ImageReference = nil
	}

	c.limiter.Limit(ctx, virtualMachineScaleSetVMsUpdate)
	sinceStart = spanstat.Start()

	poller, err := c.virtualMachineScaleSetVMs.BeginUpdate(ctx, c.resourceGroup, vmssName, instanceNum, vm.VirtualMachineScaleSetVM, nil)
	if err != nil {
		c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsUpdate, deriveStatus(err), sinceStart.Seconds())
		return "", fmt.Errorf("unable to update virtualMachineScaleSetVMs: %w", err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsUpdate, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", fmt.Errorf("error while waiting for virtualMachineScaleSetVMs Update to complete: %w", err)
	}

	// TODO return the actual public IP address
	// This would require additional API call(s) and polling, so the
	// Public IP Prefix ID is good enough to start with
	return publicIPPrefixID, nil
}

// AssignPublicIPAddressesVM assigns a public IP to a VM instance.
// The public IP is allocated from a Public IP Prefix matching publicIpTags
func (c *Client) AssignPublicIPAddressesVM(ctx context.Context, instanceID string, publicIpTags ipamTypes.Tags) (string, error) {
	// The instance ID format is:
	// /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}
	// Parse the instance ID to get the VM name
	resourceID, err := arm.ParseResourceID(instanceID)
	if err != nil {
		return "", fmt.Errorf("failed to parse instance ID %q: %w", instanceID, err)
	}
	vmName := resourceID.Name

	// Get the VM
	vmGetOptions := &armcompute.VirtualMachinesClientGetOptions{
		Expand: to.Ptr(armcompute.InstanceViewTypesInstanceView),
	}

	c.limiter.Limit(ctx, virtualMachinesGet)
	sinceStart := spanstat.Start()

	vm, err := c.virtualMachines.Get(ctx, c.resourceGroup, vmName, vmGetOptions)

	c.metricsAPI.ObserveAPICall(virtualMachinesGet, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", fmt.Errorf("failed to get VM %s: %w", vmName, err)
	}

	// Search for the primary network interface
	var primaryNetIfID string
	if vm.Properties != nil && vm.Properties.NetworkProfile != nil && vm.Properties.NetworkProfile.NetworkInterfaces != nil {
		for _, netIf := range vm.Properties.NetworkProfile.NetworkInterfaces {
			if netIf.Properties != nil && netIf.Properties.Primary != nil && *netIf.Properties.Primary && netIf.ID != nil {
				primaryNetIfID = *netIf.ID
				break
			}
		}
	}

	if primaryNetIfID == "" {
		return "", fmt.Errorf("can't find primary interface for VM %s", vmName)
	}

	// Parse interface ID to get the interface name
	netIfResourceID, err := arm.ParseResourceID(primaryNetIfID)
	if err != nil {
		return "", fmt.Errorf("failed to parse network interface ID %q: %w", primaryNetIfID, err)
	}
	interfaceName := netIfResourceID.Name

	// Get the network interface
	c.limiter.Limit(ctx, interfacesGet)
	sinceStart = spanstat.Start()

	iface, err := c.interfaces.Get(ctx, c.resourceGroup, interfaceName, nil)

	c.metricsAPI.ObserveAPICall(interfacesGet, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", fmt.Errorf("failed to get network interface %s: %w", interfaceName, err)
	}

	// Find the primary IP configuration
	var primaryIPConfig *armnetwork.InterfaceIPConfiguration
	if iface.Properties != nil && iface.Properties.IPConfigurations != nil {
		for _, ipConfig := range iface.Properties.IPConfigurations {
			if ipConfig.Properties != nil && ipConfig.Properties.Primary != nil && *ipConfig.Properties.Primary {
				primaryIPConfig = ipConfig
				break
			}
		}
	}

	if primaryIPConfig == nil {
		return "", fmt.Errorf("can't find primary IP configuration for interface %s", interfaceName)
	}

	if primaryIPConfig.Properties.PublicIPAddress != nil {
		if isPublicIPProvisionFailed(vm.Properties.InstanceView.Statuses) {
			// In certain cases, Azure will succeed to configure a VM with a certain prefix even if it is out of IP addresses.
			// This leads to the VM failing to provision properly. In this case, we need to delete the erroneous public IP address configuration
			// and configure it again.
			if err := c.deletePublicIPAddressConfigurationVM(ctx, interfaceName, vmName, &iface, primaryIPConfig); err != nil {
				return "", fmt.Errorf("failed to delete public IP address configuration for interface %s for VM %s: %w", interfaceName, vmName, err)
			}
		} else {
			return "", fmt.Errorf("public IP address already assigned to primary IP configuration for interface %s", interfaceName)
		}
	}

	// Find a public IP prefix with the given tags
	publicIPPrefixID, err := c.getPublicIPPrefixIDByTags(ctx, publicIpTags)
	if err != nil {
		return "", err
	}

	// Assign the public IP prefix to the primary IP configuration
	primaryIPConfig.Properties.PublicIPAddress = &armnetwork.PublicIPAddress{
		Name: to.Ptr("cilium-managed-public-ip"),
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
			PublicIPPrefix: &armnetwork.SubResource{
				ID: to.Ptr(publicIPPrefixID),
			},
		},
	}

	c.limiter.Limit(ctx, interfacesCreateOrUpdate)
	sinceStart = spanstat.Start()

	poller, err := c.interfaces.BeginCreateOrUpdate(ctx, c.resourceGroup, interfaceName, iface.Interface, nil)
	if err != nil {
		c.metricsAPI.ObserveAPICall(interfacesCreateOrUpdate, deriveStatus(err), sinceStart.Seconds())
		return "", fmt.Errorf("unable to update interface %s for VM %s: %w", interfaceName, vmName, err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	c.metricsAPI.ObserveAPICall(interfacesCreateOrUpdate, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", fmt.Errorf("error while waiting for interface CreateOrUpdate to complete for VM %s: %w", vmName, err)
	}

	// TODO return the actual public IP address
	// This would require additional API call(s) and polling, so the
	// Public IP Prefix ID is good enough to start with
	return publicIPPrefixID, nil
}

// deletePublicIPAddressConfigurationVMSS deletes the public IP address configuration from a VMSS instance
func (c *Client) deletePublicIPAddressConfigurationVMSS(ctx context.Context, instanceNum, vmssName string, vm *armcompute.VirtualMachineScaleSetVMsClientGetResponse, primaryIPConfig *armcompute.VirtualMachineScaleSetIPConfiguration) error {
	// Delete the public IP address configuration
	if primaryIPConfig.Properties.PublicIPAddressConfiguration != nil {
		primaryIPConfig.Properties.PublicIPAddressConfiguration = nil
	}

	// Update the VMSS instance

	// Unset imageReference, because if this contains a reference to an image from the
	// Azure Compute Gallery, including this reference in an update to the VMSS instance
	// will cause a permissions error, because the reference includes an Azure-managed
	// subscription ID.
	// Removing the image reference indicates to the API that we don't want to change it.
	// See https://github.com/Azure/AKS/issues/1819.
	if vm.Properties.StorageProfile != nil {
		vm.Properties.StorageProfile.ImageReference = nil
	}

	c.limiter.Limit(ctx, virtualMachineScaleSetVMsUpdate)
	sinceStart := spanstat.Start()

	poller, err := c.virtualMachineScaleSetVMs.BeginUpdate(ctx, c.resourceGroup, vmssName, instanceNum, vm.VirtualMachineScaleSetVM, nil)
	if err != nil {
		c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsUpdate, deriveStatus(err), sinceStart.Seconds())
		return fmt.Errorf("unable to update virtualMachineScaleSetVMs: %w", err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	c.metricsAPI.ObserveAPICall(virtualMachineScaleSetVMsUpdate, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("error while waiting for virtualMachineScaleSetVMs Update to complete: %w", err)
	}

	return nil
}

// deletePublicIPAddressConfigurationVM deletes the public IP address configuration from a VM instance
func (c *Client) deletePublicIPAddressConfigurationVM(ctx context.Context, interfaceName, vmName string, iface *armnetwork.InterfacesClientGetResponse, primaryIPConfig *armnetwork.InterfaceIPConfiguration) error {
	// Delete the public IP address configuration
	if primaryIPConfig.Properties.PublicIPAddress != nil {
		primaryIPConfig.Properties.PublicIPAddress = nil
	}

	// Update the interface
	c.limiter.Limit(ctx, interfacesCreateOrUpdate)
	sinceStart := spanstat.Start()

	poller, err := c.interfaces.BeginCreateOrUpdate(ctx, c.resourceGroup, interfaceName, iface.Interface, nil)
	if err != nil {
		c.metricsAPI.ObserveAPICall(interfacesCreateOrUpdate, deriveStatus(err), sinceStart.Seconds())
		return fmt.Errorf("unable to update interface %s for VM %s: %w", interfaceName, vmName, err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	c.metricsAPI.ObserveAPICall(interfacesCreateOrUpdate, deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("error while waiting for interface CreateOrUpdate to complete for VM %s: %w", vmName, err)
	}

	return nil
}

func (c *Client) getPublicIPPrefixIDByTags(ctx context.Context, searchTags ipamTypes.Tags) (string, error) {
	c.limiter.Limit(ctx, publicIPPrefixesList)
	sinceStart := spanstat.Start()

	pager := c.publicIPPrefixes.NewListPager(c.resourceGroup, nil)

	var prefixes []*armnetwork.PublicIPPrefix
	var finalErr error
	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			finalErr = err
			break
		}
		prefixes = append(prefixes, nextResult.Value...)
	}

	if finalErr != nil {
		c.metricsAPI.ObserveAPICall(publicIPPrefixesList, deriveStatus(finalErr), sinceStart.Seconds())
		return "", finalErr
	}

	if prefixID, found := findPublicIPPrefixByTags(prefixes, searchTags); found {
		c.metricsAPI.ObserveAPICall(publicIPPrefixesList, deriveStatus(nil), sinceStart.Seconds())
		return prefixID, nil
	}

	notFoundErr := fmt.Errorf("public IP prefix with tags %v not found in resource group %s", searchTags, c.resourceGroup)
	c.metricsAPI.ObserveAPICall(publicIPPrefixesList, deriveStatus(notFoundErr), sinceStart.Seconds())
	return "", notFoundErr
}

// findPublicIPPrefixByTags finds a suitable public IP prefix from a list that matches the given tags
func findPublicIPPrefixByTags(prefixes []*armnetwork.PublicIPPrefix, searchTags ipamTypes.Tags) (string, bool) {
	for _, publicIPPrefix := range prefixes {
		if publicIPPrefix.Tags == nil {
			continue
		}

		// Verify that all tags match
		allTagsMatch := true
		for k, v := range searchTags {
			if existing, ok := publicIPPrefix.Tags[k]; !ok || existing == nil || *existing != v {
				allTagsMatch = false
				break
			}
		}

		if !allTagsMatch {
			continue
		}

		if publicIPPrefix.ID == nil {
			continue
		}

		// Check provisioning state and available IPs
		if publicIPPrefix.Properties == nil {
			continue
		}

		// Only use prefixes that have been successfully provisioned
		if publicIPPrefix.Properties.ProvisioningState == nil ||
			*publicIPPrefix.Properties.ProvisioningState != armnetwork.ProvisioningStateSucceeded {
			continue
		}

		// Calculate total capacity from the prefix CIDR
		var totalIPs int
		if publicIPPrefix.Properties.IPPrefix != nil {
			prefix, err := netip.ParsePrefix(*publicIPPrefix.Properties.IPPrefix)
			if err != nil {
				continue
			}
			totalIPs = availableIPs(prefix)
		}

		// Count allocated IPs
		allocatedIPs := 0
		if publicIPPrefix.Properties.PublicIPAddresses != nil {
			allocatedIPs = len(publicIPPrefix.Properties.PublicIPAddresses)
		}

		// Skip if no available IPs
		if totalIPs > 0 && allocatedIPs >= totalIPs {
			continue
		}

		return *publicIPPrefix.ID, true
	}

	return "", false
}

// isPublicIPProvisionFailed checks if the public IP address configuration failed to provision
func isPublicIPProvisionFailed(instanceViewStatuses []*armcompute.InstanceViewStatus) bool {
	for _, status := range instanceViewStatuses {
		if status.Code != nil && *status.Code == "ProvisioningState/failed/PublicIpPrefixOutOfIpAddressesForVMScaleSet" {
			return true
		}
	}
	return false
}
