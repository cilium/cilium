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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
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
	virtualMachineScaleSetsList     = "VirtualMachineScaleSets.List"
	virtualMachineScaleSetVMsGet    = "VirtualMachineScaleSetVMs.Get"
	virtualMachineScaleSetVMsUpdate = "VirtualMachineScaleSetVMs.Update"
	virtualNetworksListAll          = "VirtualNetworks.ListAll"

	interfacesListVirtualMachineScaleSetNetworkInterfaces   = "Interfaces.ListVirtualMachineScaleSetNetworkInterfaces"
	interfacesListVirtualMachineScaleSetVMNetworkInterfaces = "Interfaces.ListVirtualMachineScaleSetVMNetworkInterfaces"
)

var subsysLogAttr = slog.String(logfields.LogSubsys, "azure-api")

// Client represents an Azure API client
type Client struct {
	resourceGroup             string
	interfaces                *armnetwork.InterfacesClient
	virtualNetworks           *armnetwork.VirtualNetworksClient
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
func NewClient(cloudName, subscriptionID, resourceGroup, userAssignedIdentityID string, metrics MetricsAPI, rateLimit float64, burst int, usePrimary bool) (*Client, error) {
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

	virtualMachineScaleSetVMsClient, err := armcompute.NewVirtualMachineScaleSetVMsClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	virtualMachineScaleSetsClient, err := armcompute.NewVirtualMachineScaleSetsClient(subscriptionID, credential, armClientOptions)
	if err != nil {
		return nil, err
	}

	c := &Client{
		resourceGroup:             resourceGroup,
		interfaces:                interfacesClient,
		virtualNetworks:           virtualNetworksClient,
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

// listAllNetworkInterfaces lists all Azure Interfaces in the client's resource group
func (c *Client) listAllNetworkInterfaces(ctx context.Context) ([]*armnetwork.Interface, error) {
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
	instances := ipamTypes.NewInstanceMap()

	networkInterfaces, err := c.listAllNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		if instanceID, azureInterface := parseInterface(iface, subnets, c.usePrimary); instanceID != "" {
			instances.Update(instanceID, ipamTypes.InterfaceRevision{Resource: azureInterface})
		}
	}

	return instances, nil
}

// GetInstance returns the interfaces of a given instance
func (c *Client) GetInstance(ctx context.Context, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance := ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}

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

	for _, networkInterface := range networkInterfaces {
		_, azureInterface := parseInterface(networkInterface, subnets, c.usePrimary)
		instance.Interfaces[azureInterface.ID] = ipamTypes.InterfaceRevision{Resource: azureInterface}

	}

	return &instance, nil
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
