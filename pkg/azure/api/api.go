// Copyright 2020 Authors of Cilium
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

package api

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-07-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-09-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
)

const (
	userAgent = "cilium"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "azure-api")

// Client represents an Azure API client
type Client struct {
	resourceGroup   string
	interfaces      network.InterfacesClient
	virtualnetworks network.VirtualNetworksClient
	vmss            compute.VirtualMachineScaleSetVMsClient
	vmscalesets     compute.VirtualMachineScaleSetsClient
	limiter         *helpers.ApiLimiter
	metricsAPI      MetricsAPI
	usePrimary      bool
}

// MetricsAPI represents the metrics maintained by the Azure API client
type MetricsAPI interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
}

func constructAuthorizer(cloudName, userAssignedIdentityID string) (autorest.Authorizer, error) {
	if userAssignedIdentityID != "" {
		env, err := azure.EnvironmentFromName(cloudName)
		if err != nil {
			return nil, err
		}
		msiEndpoint, err := adal.GetMSIVMEndpoint()
		if err != nil {
			return nil, err
		}

		spToken, err := adal.NewServicePrincipalTokenFromMSIWithUserAssignedID(msiEndpoint,
			env.ServiceManagementEndpoint,
			userAssignedIdentityID)
		if err != nil {
			return nil, err
		}
		return autorest.NewBearerAuthorizer(spToken), nil
	} else {
		// Authorizer based on file first and then environment variables
		authorizer, err := auth.NewAuthorizerFromFile(compute.DefaultBaseURI)
		if err == nil {
			return authorizer, nil
		}
		return auth.NewAuthorizerFromEnvironment()
	}
}

// NewClient returns a new Azure client
func NewClient(cloudName, subscriptionID, resourceGroup, userAssignedIdentityID string, metrics MetricsAPI, rateLimit float64, burst int, usePrimary bool) (*Client, error) {
	c := &Client{
		resourceGroup:   resourceGroup,
		interfaces:      network.NewInterfacesClient(subscriptionID),
		virtualnetworks: network.NewVirtualNetworksClient(subscriptionID),
		vmss:            compute.NewVirtualMachineScaleSetVMsClient(subscriptionID),
		vmscalesets:     compute.NewVirtualMachineScaleSetsClient(subscriptionID),
		metricsAPI:      metrics,
		limiter:         helpers.NewApiLimiter(metrics, rateLimit, burst),
		usePrimary:      usePrimary,
	}

	authorizer, err := constructAuthorizer(cloudName, userAssignedIdentityID)
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
		i.ID = *iface.ID
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
						if gateway := deriveGatewayIP(subnet.CIDR.IP); gateway != "" {
							i.GatewayIP = gateway
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

	result, err := c.vmss.Get(ctx, c.resourceGroup, vmssName, instanceID, compute.InstanceView)
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

	ipConfigurations := make([]compute.VirtualMachineScaleSetIPConfiguration, 0, addresses)
	for i := 0; i < addresses; i++ {
		ipConfigurations = append(ipConfigurations,
			compute.VirtualMachineScaleSetIPConfiguration{
				Name: to.StringPtr(generateIpConfigName()),
				VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
					PrivateIPAddressVersion: compute.IPv4,
					Subnet:                  &compute.APIEntityReference{ID: to.StringPtr(subnetID)},
				},
			},
		)
	}

	ipConfigurations = append(*netIfConfig.IPConfigurations, ipConfigurations...)
	netIfConfig.IPConfigurations = &ipConfigurations

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
	iface, err := c.interfaces.Get(ctx, c.resourceGroup, interfaceName, "")
	if err != nil {
		return fmt.Errorf("failed to get standalone instance's interface %s: %s", interfaceName, err)
	}

	ipConfigurations := make([]network.InterfaceIPConfiguration, 0, addresses)
	for i := 0; i < addresses; i++ {
		ipConfigurations = append(ipConfigurations, network.InterfaceIPConfiguration{
			Name: to.StringPtr(generateIpConfigName()),
			InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAllocationMethod: network.Dynamic,
				Subnet: &network.Subnet{
					ID: to.StringPtr(subnetID),
				},
			},
		})
	}

	ipConfigurations = append(*iface.IPConfigurations, ipConfigurations...)
	iface.IPConfigurations = &ipConfigurations

	future, err := c.interfaces.CreateOrUpdate(ctx, c.resourceGroup, interfaceName, iface)
	if err != nil {
		return fmt.Errorf("unable to update interface %s: %s", interfaceName, err)
	}

	if err := future.WaitForCompletionRef(ctx, c.interfaces.Client); err != nil {
		return fmt.Errorf("error while waiting for interface.CreateOrUpdate() to complete for %s: %s", interfaceName, err)
	}

	return nil
}
