// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/version"
)

var (
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, "azure-api")
	userAgent = fmt.Sprintf("cilium/%s", version.Version)
)

// Client represents an Azure API client
type Client struct {
	resourceGroup   string
	interfaces      *armnetwork.InterfacesClient
	virtualnetworks *armnetwork.VirtualNetworksClient
	vmss            *armcompute.VirtualMachineScaleSetVMsClient
	vmscalesets     *armcompute.VirtualMachineScaleSetsClient
	limiter         *helpers.APILimiter
	metricsAPI      MetricsAPI
	usePrimary      bool
}

// MetricsAPI represents the metrics maintained by the Azure API client
type MetricsAPI interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
}

var environments = map[string]cloud.Configuration{
	"AZURECHINACLOUD":        cloud.AzureChina,
	"AZURECLOUD":             cloud.AzurePublic,
	"AZUREGERMANCLOUD":       cloud.AzurePublic,
	"AZUREPUBLICCLOUD":       cloud.AzurePublic,
	"AZUREUSGOVERNMENT":      cloud.AzureGovernment,
	"AZUREUSGOVERNMENTCLOUD": cloud.AzureGovernment,
}

// cloudConfigurationFromName returns cloud configuration based on the common name specified.
func cloudConfigurationFromName(name string) (cloud.Configuration, error) {
	name = strings.ToUpper(name)
	env, ok := environments[name]
	if !ok {
		return env, fmt.Errorf("There is no cloud configuration matching the name %q", name)
	}

	return env, nil
}

func constructCredential(policyClientOptions policy.ClientOptions, clientID string) (azcore.TokenCredential, error) {
	if clientID != "" {
		options := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: policyClientOptions, ID: azidentity.ClientID(clientID)}
		managedIdentityCredential, err := azidentity.NewManagedIdentityCredential(options)
		if err != nil {
			return nil, err
		}
		return azcore.TokenCredential(managedIdentityCredential), nil
	} else {
		options := &azidentity.EnvironmentCredentialOptions{ClientOptions: policyClientOptions}
		environmentCredential, err := azidentity.NewEnvironmentCredential(options)
		if err != nil {
			return nil, err
		}
		return azcore.TokenCredential(environmentCredential), nil
	}
}

// NewClient returns a new Azure client
func NewClient(cloudName, subscriptionID, resourceGroup, userAssignedIdentityID string, metrics MetricsAPI, rateLimit float64, burst int, usePrimary bool) (*Client, error) {
	cloudConfiguration, err := cloudConfigurationFromName(cloudName)
	if err != nil {
		return nil, err
	}
	telemetry := policy.TelemetryOptions{
		ApplicationID: userAgent,
	}
	policyClientOptions := policy.ClientOptions{
		Cloud:     cloudConfiguration,
		Telemetry: telemetry,
	}
	credential, err := constructCredential(policyClientOptions, userAssignedIdentityID)
	if err != nil {
		return nil, err
	}
	options := &arm.ClientOptions{
		ClientOptions: policyClientOptions,
	}

	c := &Client{
		resourceGroup: resourceGroup,
		metricsAPI:    metrics,
		limiter:       helpers.NewAPILimiter(metrics, rateLimit, burst),
		usePrimary:    usePrimary,
	}

	c.interfaces, err = armnetwork.NewInterfacesClient(subscriptionID, credential, options)
	if err != nil {
		return nil, err
	}
	c.virtualnetworks, err = armnetwork.NewVirtualNetworksClient(subscriptionID, credential, options)
	if err != nil {
		return nil, err
	}
	c.vmss, err = armcompute.NewVirtualMachineScaleSetVMsClient(subscriptionID, credential, options)
	if err != nil {
		return nil, err
	}
	c.vmscalesets, err = armcompute.NewVirtualMachineScaleSetsClient(subscriptionID, credential, options)
	if err != nil {
		return nil, err
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

// describeNetworkInterfaces lists all Azure Interfaces in the client's resource group
func (c *Client) describeNetworkInterfaces(ctx context.Context) ([]armnetwork.Interface, error) {
	networkInterfaces, err := c.vmssNetworkInterfaces(ctx)
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
func (c *Client) vmNetworkInterfaces(ctx context.Context) ([]armnetwork.Interface, error) {
	var networkInterfaces []armnetwork.Interface

	pager := c.interfaces.NewListPager(c.resourceGroup, nil)
	for pager.More() {
		c.limiter.Limit(ctx, "Interfaces.ListPager.NextPage")
		sinceStart := spanstat.Start()
		page, err := pager.NextPage(ctx)
		c.metricsAPI.ObserveAPICall("Interfaces.ListPager.NextPage", deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}
		for _, intf := range page.Value {
			if intf.Name != nil {
				networkInterfaces = append(networkInterfaces, *intf)
			}
		}
	}

	return networkInterfaces, nil
}

// vmssNetworkInterfaces list all interfaces from VMS in Scale Sets in the client's resource group
func (c *Client) vmssNetworkInterfaces(ctx context.Context) ([]armnetwork.Interface, error) {
	var networkInterfaces []armnetwork.Interface

	pager := c.vmscalesets.NewListPager(c.resourceGroup, nil)
	for pager.More() {
		c.limiter.Limit(ctx, "VirtualMachineScaleSets.ListPager.NextPage")
		sinceStart := spanstat.Start()
		page, err := pager.NextPage(ctx)
		c.metricsAPI.ObserveAPICall("VirtualMachineScaleSets.ListPager.NextPage", deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}

		for _, scaleset := range page.Value {
			if scaleset.Name != nil {
				pager2 := c.interfaces.NewListVirtualMachineScaleSetNetworkInterfacesPager(c.resourceGroup, *scaleset.Name, nil)
				for pager2.More() {
					c.limiter.Limit(ctx, "Interfaces.ListVirtualMachineScaleSetNetworkInterfacesPager.NextPage")
					sinceStart := spanstat.Start()
					page2, err2 := pager2.NextPage(ctx)
					c.metricsAPI.ObserveAPICall("Interfaces.ListVirtualMachineScaleSetNetworkInterfacesPager.NextPage", deriveStatus(err2), sinceStart.Seconds())
					if err2 != nil {
						return nil, err2
					}
					for _, networkInterface := range page2.Value {
						networkInterfaces = append(networkInterfaces, *networkInterface)
					}
				}
			}
		}
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
		for _, ip := range iface.Properties.IPConfigurations {
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
						if subnet.CIDR != nil {
							i.CIDR = subnet.CIDR.String()
						}
						if gateway := deriveGatewayIP(subnet.CIDR.IP); gateway != "" {
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
func deriveGatewayIP(subnetIP net.IP) string {
	addr := subnetIP.To4()
	return net.IPv4(addr[0], addr[1], addr[2], addr[3]+1).String()
}

// GetInstances returns the list of all instances including all attached
// interfaces as instanceMap
func (c *Client) GetInstances(ctx context.Context, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	networkInterfaces, err := c.describeNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		if id, azureInterface := parseInterface(&iface, subnets, c.usePrimary); id != "" {
			instances.Update(id, ipamTypes.InterfaceRevision{Resource: azureInterface})
		}
	}

	return instances, nil
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs(ctx context.Context) ([]armnetwork.VirtualNetwork, error) {
	pager := c.virtualnetworks.NewListAllPager(nil)
	var vpcs []armnetwork.VirtualNetwork
	for pager.More() {
		c.limiter.Limit(ctx, "VirtualNetworks.ListAllPager.NextPage")
		sinceStart := spanstat.Start()
		page, err := pager.NextPage(ctx)
		c.metricsAPI.ObserveAPICall("VirtualNetworks.ListAllPager.NextPage", deriveStatus(err), sinceStart.Seconds())
		if err != nil {
			return nil, err
		}
		for _, vpc := range page.Value {
			vpcs = append(vpcs, *vpc)
		}
	}

	return vpcs, nil
}

func parseSubnet(subnet *armnetwork.Subnet) (s *ipamTypes.Subnet) {
	s = &ipamTypes.Subnet{ID: *subnet.ID}
	if subnet.Name != nil {
		s.Name = *subnet.Name
	}

	if subnet.Properties.AddressPrefix != nil {
		c, err := cidr.ParseCIDR(*subnet.Properties.AddressPrefix)
		if err != nil {
			return nil
		}
		s.CIDR = c
		if subnet.Properties.IPConfigurations != nil {
			s.AvailableAddresses = c.AvailableIPs() - len(subnet.Properties.IPConfigurations)
		}
	}

	return
}

// GetVpcsAndSubnets retrieves and returns all Vpcs
func (c *Client) GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}
	subnets := ipamTypes.SubnetMap{}

	vpcList, err := c.describeVpcs(ctx)
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

	c.limiter.Limit(ctx, "VirtualMachineScaleSetVMs.Get")
	sinceStart := spanstat.Start()
	result, err := c.vmss.Get(ctx, c.resourceGroup, vmssName, instanceID, &armcompute.VirtualMachineScaleSetVMsClientGetOptions{Expand: to.Ptr(armcompute.InstanceViewTypesInstanceView)})
	c.metricsAPI.ObserveAPICall("VirtualMachineScaleSetVMs.Get", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get VM %s from VMSS %s: %s", instanceID, vmssName, err)
	}

	parameters := result.VirtualMachineScaleSetVM

	// Search for the existing network interface configuration
	if parameters.Properties.NetworkProfileConfiguration != nil {
		for _, networkInterfaceConfiguration := range parameters.Properties.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
			if *networkInterfaceConfiguration.Name == interfaceName {
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
	for i := 0; i < addresses; i++ {
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
	if parameters.Properties.StorageProfile != nil {
		parameters.Properties.StorageProfile.ImageReference = nil
	}

	c.limiter.Limit(ctx, "VirtualMachineScaleSetVMs.BeginUpdate")
	sinceStart = spanstat.Start()
	poller, err := c.vmss.BeginUpdate(ctx, c.resourceGroup, vmssName, instanceID, parameters, nil)
	defer c.metricsAPI.ObserveAPICall("VirtualMachineScaleSetVMs.BeginUpdate", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("unable to update virtualmachinescaleset: %s", err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("error while waiting for virtualmachinescalesets.BeginUpdate() to complete: %s", err)
	}
	return nil
}

// AssignPrivateIpAddressesVM assign a private IP to an interface attached to a standalone instance
func (c *Client) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error {
	c.limiter.Limit(ctx, "Interfaces.Get")
	sinceStart := spanstat.Start()
	iface, err := c.interfaces.Get(ctx, c.resourceGroup, interfaceName, nil)
	c.metricsAPI.ObserveAPICall("Interfaces.Get", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get standalone instance's interface %s: %s", interfaceName, err)
	}

	parameters := iface.Interface
	// All IPConfigurations on the NIC should reference the same set of Application Security Groups (ASGs).
	// So we should first fetch the set of ASGs referenced by other IPConfigurations so that it can be
	// added to the new IPConfigurations.
	var appSecurityGroups []*armnetwork.ApplicationSecurityGroup
	if ipConfigs := parameters.Properties.IPConfigurations; len(ipConfigs) > 0 {
		appSecurityGroups = ipConfigs[0].Properties.ApplicationSecurityGroups
	}

	ipConfigurations := make([]*armnetwork.InterfaceIPConfiguration, 0, addresses)
	for i := 0; i < addresses; i++ {
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

	ipConfigurations = append(parameters.Properties.IPConfigurations, ipConfigurations...)
	parameters.Properties.IPConfigurations = ipConfigurations

	c.limiter.Limit(ctx, "Interfaces.BeginCreateOrUpdate")
	sinceStart = spanstat.Start()
	poller, err := c.interfaces.BeginCreateOrUpdate(ctx, c.resourceGroup, interfaceName, parameters, nil)
	defer c.metricsAPI.ObserveAPICall("Interfaces.BeginCreateOrUpdate", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("unable to update interface %s: %s", interfaceName, err)
	}

	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("error while waiting for interface.BeginCreateOrUpdate() to complete for %s: %s", interfaceName, err)
	}

	return nil
}
