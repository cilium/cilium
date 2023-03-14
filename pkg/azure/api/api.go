// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-03-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2020-11-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rand"
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
	interfaces      network.InterfacesClient
	virtualnetworks network.VirtualNetworksClient
	vmss            compute.VirtualMachineScaleSetVMsClient
	vmscalesets     compute.VirtualMachineScaleSetsClient
	limiter         *helpers.APILimiter
	metricsAPI      MetricsAPI
	usePrimary      bool
}

// MetricsAPI represents the metrics maintained by the Azure API client
type MetricsAPI interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
}

func constructAuthorizer(env azure.Environment, userAssignedIdentityID string) (autorest.Authorizer, error) {
	if userAssignedIdentityID != "" {
		spToken, err := adal.NewServicePrincipalTokenFromManagedIdentity(env.ServiceManagementEndpoint, &adal.ManagedIdentityOptions{
			ClientID: userAssignedIdentityID,
		})
		if err != nil {
			return nil, err
		}

		return autorest.NewBearerAuthorizer(spToken), nil
	} else {
		// Authorizer based on file first and then environment variables
		authorizer, err := auth.NewAuthorizerFromFile(env.ResourceManagerEndpoint)
		if err == nil {
			return authorizer, nil
		}
		return auth.NewAuthorizerFromEnvironment()
	}
}

// NewClient returns a new Azure client
func NewClient(cloudName, subscriptionID, resourceGroup, userAssignedIdentityID string, metrics MetricsAPI, rateLimit float64, burst int, usePrimary bool) (*Client, error) {
	azureEnv, err := azure.EnvironmentFromName(cloudName)
	if err != nil {
		return nil, err
	}

	c := &Client{
		resourceGroup:   resourceGroup,
		interfaces:      network.NewInterfacesClientWithBaseURI(azureEnv.ResourceManagerEndpoint, subscriptionID),
		virtualnetworks: network.NewVirtualNetworksClientWithBaseURI(azureEnv.ResourceManagerEndpoint, subscriptionID),
		vmss:            compute.NewVirtualMachineScaleSetVMsClientWithBaseURI(azureEnv.ResourceManagerEndpoint, subscriptionID),
		vmscalesets:     compute.NewVirtualMachineScaleSetsClientWithBaseURI(azureEnv.ResourceManagerEndpoint, subscriptionID),
		metricsAPI:      metrics,
		limiter:         helpers.NewAPILimiter(metrics, rateLimit, burst),
		usePrimary:      usePrimary,
	}

	authorizer, err := constructAuthorizer(azureEnv, userAssignedIdentityID)
	if err != nil {
		return nil, err
	}

	c.interfaces.Authorizer = authorizer
	c.interfaces.AddToUserAgent(userAgent)
	c.virtualnetworks.Authorizer = authorizer
	c.virtualnetworks.AddToUserAgent(userAgent)
	c.vmss.Authorizer = authorizer
	c.vmss.AddToUserAgent(userAgent)
	c.vmscalesets.Authorizer = authorizer
	c.vmscalesets.AddToUserAgent(userAgent)

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
func (c *Client) describeNetworkInterfaces(ctx context.Context) ([]network.Interface, error) {
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
func (c *Client) vmNetworkInterfaces(ctx context.Context) ([]network.Interface, error) {
	var networkInterfaces []network.Interface

	c.limiter.Limit(ctx, "Interfaces.ListComplete")
	sinceStart := spanstat.Start()
	result, err := c.interfaces.ListComplete(ctx, c.resourceGroup)
	c.metricsAPI.ObserveAPICall("Interfaces.ListComplete", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	for result.NotDone() {
		if err != nil {
			return nil, err
		}
		err = result.Next()

		intf := result.Value()

		if intf.Name == nil {
			continue
		}
		networkInterfaces = append(networkInterfaces, intf)
	}

	return networkInterfaces, nil
}

// vmssNetworkInterfaces list all interfaces from VMS in Scale Sets in the client's resource group
func (c *Client) vmssNetworkInterfaces(ctx context.Context) ([]network.Interface, error) {
	var networkInterfaces []network.Interface

	c.limiter.Limit(ctx, "VirtualMachineScaleSets.ListAll")
	sinceStart := spanstat.Start()
	result, err := c.vmscalesets.ListComplete(ctx, c.resourceGroup)
	c.metricsAPI.ObserveAPICall("VirtualMachineScaleSets.ListAll", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	for result.NotDone() {
		if err != nil {
			return nil, err
		}

		scaleset := result.Value()
		err = result.Next()

		if scaleset.Name == nil {
			continue
		}

		c.limiter.Limit(ctx, "Interfaces.ListAll")
		sinceStart := spanstat.Start()
		result2, err2 := c.interfaces.ListVirtualMachineScaleSetNetworkInterfacesComplete(ctx, c.resourceGroup, *scaleset.Name)
		c.metricsAPI.ObserveAPICall("Interfaces.ListVirtualMachineScaleSetNetworkInterfacesComplete", deriveStatus(err2), sinceStart.Seconds())
		if err2 != nil {
			// For scale set created by AKS node group (otherwise it will return an empty list) without any instances API will return not found. Then it can be skipped.
			if v, ok := err2.(autorest.DetailedError); ok && v.StatusCode == http.StatusNotFound {
				continue
			}
			return nil, err2
		}

		for result2.NotDone() {
			if err2 != nil {
				return nil, err2
			}

			networkInterfaces = append(networkInterfaces, result2.Value())
			err2 = result2.Next()
		}
	}

	return networkInterfaces, nil
}

// parseInterfaces parses a network.Interface as returned by the Azure API
// converts it into a types.AzureInterface
func parseInterface(iface *network.Interface, subnets ipamTypes.SubnetMap, usePrimary bool) (instanceID string, i *types.AzureInterface) {
	i = &types.AzureInterface{}

	if iface.VirtualMachine != nil && iface.VirtualMachine.ID != nil {
		instanceID = strings.ToLower(*iface.VirtualMachine.ID)
	}

	if iface.MacAddress != nil {
		// Azure API reports MAC addresses as AA-BB-CC-DD-EE-FF
		i.MAC = strings.ReplaceAll(*iface.MacAddress, "-", ":")
	}

	if iface.ID != nil {
		i.SetID(*iface.ID)
	}

	if iface.Name != nil {
		i.Name = *iface.Name
	}

	if iface.NetworkSecurityGroup != nil {
		if iface.NetworkSecurityGroup.ID != nil {
			i.SecurityGroup = *iface.NetworkSecurityGroup.ID
		}
	}

	if iface.IPConfigurations != nil {
		for _, ip := range *iface.IPConfigurations {
			if !usePrimary && ip.Primary != nil && *ip.Primary {
				continue
			}
			if ip.PrivateIPAddress != nil {
				addr := types.AzureAddress{
					IP:    *ip.PrivateIPAddress,
					State: strings.ToLower(string(ip.ProvisioningState)),
				}

				if ip.Subnet != nil {
					addr.Subnet = *ip.Subnet.ID
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
func (c *Client) describeVpcs(ctx context.Context) ([]network.VirtualNetwork, error) {
	c.limiter.Limit(ctx, "VirtualNetworks.List")

	sinceStart := spanstat.Start()
	result, err := c.virtualnetworks.ListAllComplete(ctx)
	c.metricsAPI.ObserveAPICall("virtualnetworks.ListAll", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	var vpcs []network.VirtualNetwork
	for result.NotDone() {
		if err != nil {
			return nil, err
		}

		vpcs = append(vpcs, result.Value())
		err = result.Next()
	}

	return vpcs, nil
}

func parseSubnet(subnet *network.Subnet) (s *ipamTypes.Subnet) {
	s = &ipamTypes.Subnet{ID: *subnet.ID}
	if subnet.Name != nil {
		s.Name = *subnet.Name
	}

	if subnet.AddressPrefix != nil {
		c, err := cidr.ParseCIDR(*subnet.AddressPrefix)
		if err != nil {
			return nil
		}
		s.CIDR = c
		if subnet.IPConfigurations != nil {
			s.AvailableAddresses = c.AvailableIPs() - len(*subnet.IPConfigurations)
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

		if v.Subnets != nil {
			for _, subnet := range *v.Subnets {
				if subnet.ID == nil {
					continue
				}
				if s := parseSubnet(&subnet); s != nil {
					subnets[*subnet.ID] = s
				}
			}
		}
	}

	return vpcs, subnets, nil
}

func generateIpConfigName() string {
	return rand.RandomStringWithPrefix("Cilium-", 8)
}

// AssignPrivateIpAddressesVMSS assign a private IP to an interface attached to a VMSS instance
func (c *Client) AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error {
	var netIfConfig *compute.VirtualMachineScaleSetNetworkConfiguration

	c.limiter.Limit(ctx, "VirtualMachineScaleSetVMs.Get")
	result, err := c.vmss.Get(ctx, c.resourceGroup, vmssName, instanceID, compute.InstanceViewTypesInstanceView)
	if err != nil {
		return fmt.Errorf("failed to get VM %s from VMSS %s: %s", instanceID, vmssName, err)
	}

	// Search for the existing network interface configuration
	if result.NetworkProfileConfiguration != nil {
		for _, networkInterfaceConfiguration := range *result.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
			if to.String(networkInterfaceConfiguration.Name) == interfaceName {
				netIfConfig = &networkInterfaceConfiguration
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
	var appSecurityGroups *[]compute.SubResource
	if ipConfigs := *netIfConfig.IPConfigurations; len(ipConfigs) > 0 {
		appSecurityGroups = ipConfigs[0].ApplicationSecurityGroups
	}

	ipConfigurations := make([]compute.VirtualMachineScaleSetIPConfiguration, 0, addresses)
	for i := 0; i < addresses; i++ {
		ipConfigurations = append(ipConfigurations,
			compute.VirtualMachineScaleSetIPConfiguration{
				Name: to.StringPtr(generateIpConfigName()),
				VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
					ApplicationSecurityGroups: appSecurityGroups,
					PrivateIPAddressVersion:   compute.IPVersionIPv4,
					Subnet:                    &compute.APIEntityReference{ID: to.StringPtr(subnetID)},
				},
			},
		)
	}

	ipConfigurations = append(*netIfConfig.IPConfigurations, ipConfigurations...)
	netIfConfig.IPConfigurations = &ipConfigurations

	// Unset imageReference, because if this contains a reference to an image from the
	// Azure Compute Gallery, including this reference in an update to the VMSS instance
	// will cause a permissions error, because the reference includes an Azure-managed
	// subscription ID.
	// Removing the image reference indicates to the API that we don't want to change it.
	// See https://github.com/Azure/AKS/issues/1819.
	if result.StorageProfile != nil {
		result.StorageProfile.ImageReference = nil
	}

	c.limiter.Limit(ctx, "VirtualMachineScaleSetVMs.Update")
	future, err := c.vmss.Update(ctx, c.resourceGroup, vmssName, instanceID, result)
	if err != nil {
		return fmt.Errorf("unable to update virtualmachinescaleset: %s", err)
	}

	if err := future.WaitForCompletionRef(ctx, c.vmss.Client); err != nil {
		return fmt.Errorf("error while waiting for virtualmachinescalesets.Update() to complete: %s", err)
	}

	return nil
}

// AssignPrivateIpAddressesVM assign a private IP to an interface attached to a standalone instance
func (c *Client) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error {
	c.limiter.Limit(ctx, "Interfaces.Get")
	iface, err := c.interfaces.Get(ctx, c.resourceGroup, interfaceName, "")
	if err != nil {
		return fmt.Errorf("failed to get standalone instance's interface %s: %s", interfaceName, err)
	}

	// All IPConfigurations on the NIC should reference the same set of Application Security Groups (ASGs).
	// So we should first fetch the set of ASGs referenced by other IPConfigurations so that it can be
	// added to the new IPConfigurations.
	var appSecurityGroups *[]network.ApplicationSecurityGroup
	if ipConfigs := *iface.IPConfigurations; len(ipConfigs) > 0 {
		appSecurityGroups = ipConfigs[0].ApplicationSecurityGroups
	}

	ipConfigurations := make([]network.InterfaceIPConfiguration, 0, addresses)
	for i := 0; i < addresses; i++ {
		ipConfigurations = append(ipConfigurations, network.InterfaceIPConfiguration{
			Name: to.StringPtr(generateIpConfigName()),
			InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
				ApplicationSecurityGroups: appSecurityGroups,
				PrivateIPAllocationMethod: network.IPAllocationMethodDynamic,
				Subnet: &network.Subnet{
					ID: to.StringPtr(subnetID),
				},
			},
		})
	}

	ipConfigurations = append(*iface.IPConfigurations, ipConfigurations...)
	iface.IPConfigurations = &ipConfigurations

	c.limiter.Limit(ctx, "Interfaces.CreateOrUpdate")
	future, err := c.interfaces.CreateOrUpdate(ctx, c.resourceGroup, interfaceName, iface)
	if err != nil {
		return fmt.Errorf("unable to update interface %s: %s", interfaceName, err)
	}

	if err := future.WaitForCompletionRef(ctx, c.interfaces.Client); err != nil {
		return fmt.Errorf("error while waiting for interface.CreateOrUpdate() to complete for %s: %s", interfaceName, err)
	}

	return nil
}
