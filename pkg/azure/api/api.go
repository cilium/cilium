// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-08-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-08-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/sirupsen/logrus"
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

	// azureAPIVersion is automatically detected from the imported Azure SDK package at build time
	azureAPIVersion = detectAzureAPIVersion()
)

// detectAzureAPIVersion gets the imported Azure SDK version
func detectAzureAPIVersion() string {
	// Use reflection to get the package path of the network client
	// This happens once at package initialization, not on every call
	clientType := reflect.TypeOf((*network.SubnetsClient)(nil)).Elem()
	packagePath := clientType.PkgPath()

	// Extract version from package path: github.com/Azure/azure-sdk-for-go/services/network/mgmt/{VERSION}/network
	versionPattern := regexp.MustCompile(`/mgmt/([0-9]{4}-[0-9]{2}-[0-9]{2})/`)
	if matches := versionPattern.FindStringSubmatch(packagePath); len(matches) > 1 {
		detectedVersion := matches[1]
		log.WithField("apiVersion", detectedVersion).Info("Detected Azure API version from imported SDK package")
		return detectedVersion
	}

	// This should never happen unless the SDK package structure changes dramatically
	log.Warning("Could not detect Azure API version from SDK package, using fallback")
	return "2021-08-01"
}

// Client represents an Azure API client
type Client struct {
	subscriptionID  string
	resourceGroup   string
	interfaces      network.InterfacesClient
	virtualnetworks network.VirtualNetworksClient
	subnets         network.SubnetsClient
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
		subscriptionID:  subscriptionID,
		resourceGroup:   resourceGroup,
		interfaces:      network.NewInterfacesClientWithBaseURI(azureEnv.ResourceManagerEndpoint, subscriptionID),
		virtualnetworks: network.NewVirtualNetworksClientWithBaseURI(azureEnv.ResourceManagerEndpoint, subscriptionID),
		subnets:         network.NewSubnetsClientWithBaseURI(azureEnv.ResourceManagerEndpoint, subscriptionID),
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
	c.subnets.Authorizer = authorizer
	c.subnets.AddToUserAgent(userAgent)
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
			var v autorest.DetailedError
			if errors.As(err2, &v) && v.StatusCode == http.StatusNotFound {
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

// azureSubnetIDRegex matches Azure subnet resource IDs and captures resource group, vnet and subnet names
var azureSubnetIDRegex = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)/subnets/([^/]+)$`)

// expectedCaptureGroups is the expected number of regex capture groups plus the full match
// (full match + resourceGroup + virtualNetworkName + subnetName = 4 total)
const expectedCaptureGroups = 4

// parseSubnetID extracts the resource group, virtual network name and subnet name from an Azure subnet ID.
// Captures resourceGroup, virtualNetworkName and subnetName from the full Azure resource ID.
// Expected format: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{virtualNetworkName}/subnets/{subnetName}
func parseSubnetID(subnetID string) (resourceGroupName, vnetName, subnetName string, err error) {
	matches := azureSubnetIDRegex.FindStringSubmatch(subnetID)
	if len(matches) != expectedCaptureGroups {
		return "", "", "", fmt.Errorf("invalid Azure subnet ID format: %s", subnetID)
	}

	resourceGroupName = matches[1]
	vnetName = matches[2]
	subnetName = matches[3]

	return resourceGroupName, vnetName, subnetName, nil
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

// GetNodesSubnets retrieves subnet information for node interfaces by making targeted API calls
// instead of listing all VNets subscription-wide. This method only queries the specific subnets
// that are referenced by existing node network interfaces.
// Uses raw HTTP pagination to accurately handle subnets with many IP configurations
// and Azure may return pagination links in the response.
// This method is used to get the subnet details for node interfaces.
func (c *Client) GetNodesSubnets(ctx context.Context, subnetIDs []string) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}

	for _, subnetID := range subnetIDs {
		// Parse subnet ID to extract resource group, vnet and subnet names
		resourceGroup, vnetName, subnetName, err := parseSubnetID(subnetID)
		if err != nil {
			log.WithError(err).WithField("subnetID", subnetID).Warning("Failed to parse subnet ID, skipping")
			continue
		}

		// Use pagination-aware subnet query for accurate IP configuration counting
		subnet, err := c.getSubnetWithPagination(ctx, c.subscriptionID, resourceGroup, vnetName, subnetName)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"subnetID":      subnetID,
				"resourceGroup": resourceGroup,
				"vnetName":      vnetName,
				"subnetName":    subnetName,
			}).Warning("Failed to get subnet details, skipping")
			continue
		}

		if subnet != nil {
			subnets[subnetID] = subnet
			log.WithFields(logrus.Fields{
				"subnetID":           subnetID,
				"availableAddresses": subnet.AvailableAddresses,
				"cidr":               subnet.CIDR,
			}).Debug("Successfully retrieved subnet details with pagination")
		}
	}

	return subnets, nil
}

// subnetResponseRaw represents the raw HTTP response structure for subnet API calls
type subnetResponseRaw struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Properties struct {
		AddressPrefix    *string              `json:"addressPrefix,omitempty"`
		AddressPrefixes  *[]string            `json:"addressPrefixes,omitempty"`
		IPConfigurations []ipConfigurationRef `json:"ipConfigurations,omitempty"`
	} `json:"properties"`
	NextLink string `json:"nextLink,omitempty"`
}

// ipConfigurationRef represents a reference to an IP configuration in the raw response
type ipConfigurationRef struct {
	ID string `json:"id"`
}

// getSubnetWithPagination retrieves a subnet with full IP configuration pagination using raw HTTP calls
// Azure may return nextLink if more than some amount of IP configuration limit
func (c *Client) getSubnetWithPagination(ctx context.Context, subscriptionID, resourceGroup, vnetName, subnetName string) (*ipamTypes.Subnet, error) {
	// Build initial API URL using the same version as SDK
	baseURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/%s",
		subscriptionID, resourceGroup, vnetName, subnetName)

	initialURL := fmt.Sprintf("%s?api-version=%s", baseURL, azureAPIVersion)

	log := log.WithFields(logrus.Fields{
		"subscriptionID": subscriptionID,
		"resourceGroup":  resourceGroup,
		"vnetName":       vnetName,
		"subnetName":     subnetName,
		"apiVersion":     azureAPIVersion,
		"subsys":         "azure-pagination",
	})

	log.Info("Starting subnet pagination query.")

	// Collect all IP configurations across all pages
	var allIPConfigs []ipConfigurationRef
	var firstPageSubnetInfo *subnetResponseRaw
	pageCount := 0
	nextURL := initialURL

	for nextURL != "" {
		pageCount++
		pageLog := log.WithField("page", pageCount)

		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request for page %d: %w", pageCount, err)
		}

		// Add authentication using the same mechanism as the SDK
		// Get a bearer token from the authorizer
		if bearerAuth, ok := c.subnets.Client.Authorizer.(*autorest.BearerAuthorizer); ok {
			if tokenProvider := bearerAuth.TokenProvider(); tokenProvider != nil {
				token := tokenProvider.OAuthToken()
				if token == "" {
					return nil, fmt.Errorf("failed to get OAuth token for page %d: token is empty", pageCount)
				}
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			}
		} else {
			// For other authorizer types, we'll have to fallback to the SDK method
			pageLog.Warning("Non-bearer authorizer detected - falling back to SDK method for this subnet")
			return nil, fmt.Errorf("unsupported authorizer type for pagination - please use bearer token authentication")
		}

		req.Header.Set("User-Agent", c.subnets.Client.UserAgent)
		req.Header.Set("Accept", "application/json")

		pageLog.WithField("url", nextURL).Debug("Making paginated HTTP request")

		// Make HTTP request
		c.limiter.Limit(ctx, "Subnets.GetWithPagination")
		sinceStart := spanstat.Start()

		httpClient := &http.Client{Timeout: 30 * time.Second}
		resp, err := httpClient.Do(req)

		c.metricsAPI.ObserveAPICall("Subnets.GetWithPagination", deriveStatus(err), sinceStart.Seconds())

		if err != nil {
			return nil, fmt.Errorf("HTTP request failed for page %d: %w", pageCount, err)
		}
		defer resp.Body.Close()

		// Check HTTP status
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("HTTP request failed for page %d with status %d: %s", pageCount, resp.StatusCode, string(body))
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body for page %d: %w", pageCount, err)
		}

		// Parse JSON response
		var subnetResp subnetResponseRaw
		if err := json.Unmarshal(body, &subnetResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response for page %d: %w", pageCount, err)
		}

		// Store subnet metadata from the first page
		if pageCount == 1 {
			firstPageSubnetInfo = &subnetResp
		}

		// Add IP configurations from this page
		ipConfigsOnPage := len(subnetResp.Properties.IPConfigurations)
		allIPConfigs = append(allIPConfigs, subnetResp.Properties.IPConfigurations...)

		pageLog.WithFields(logrus.Fields{
			"ipConfigsOnPage": ipConfigsOnPage,
			"totalSoFar":      len(allIPConfigs),
			"hasNextLink":     subnetResp.NextLink != "",
		}).Info("Processed subnet pagination page")

		// Check for next page
		nextURL = subnetResp.NextLink
		if nextURL != "" {
			// Sanity check nextLink format as mentioned in requirements
			if !strings.Contains(nextURL, "$skiptoken") && !strings.Contains(nextURL, "skiptoken") {
				pageLog.WithField("suspiciousNextLink", nextURL).Warning("Suspicious nextLink format detected, stopping pagination for safety")
				break
			}
		}
	}

	totalIPConfigs := len(allIPConfigs)

	// Final logging with nextLink-based pagination detection
	paginationUsed := pageCount > 1
	log.WithFields(logrus.Fields{
		"totalPages":     pageCount,
		"totalIPConfigs": totalIPConfigs,
		"paginationUsed": paginationUsed,
	}).Info("Completed subnet pagination query")

	// Log pagination details based on actual response behavior
	if paginationUsed {
		log.WithFields(logrus.Fields{
			"totalIPConfigs": totalIPConfigs,
			"pageCount":      pageCount,
		}).Info("Pagination was required - subnet has more IP configurations than single page limit")
	} else {
		log.WithField("totalIPConfigs", totalIPConfigs).Debug("No pagination needed - all IP configurations retrieved in single page")
	}

	// Ensure we have subnet info from the first page
	if firstPageSubnetInfo == nil {
		return nil, fmt.Errorf("no subnet information retrieved from first page")
	}

	// Build final subnet object using the first page subnet info and total IP config count
	subnet := &ipamTypes.Subnet{
		ID:   firstPageSubnetInfo.ID,
		Name: firstPageSubnetInfo.Name,
	}

	// Parse CIDR from the first page subnet info
	if firstPageSubnetInfo.Properties.AddressPrefix != nil {
		c, err := cidr.ParseCIDR(*firstPageSubnetInfo.Properties.AddressPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR %s: %w", *firstPageSubnetInfo.Properties.AddressPrefix, err)
		}
		subnet.CIDR = c
		// Calculate available addresses using total IP configurations from all pages
		subnet.AvailableAddresses = c.AvailableIPs() - totalIPConfigs
	}

	log.WithFields(logrus.Fields{
		"subnetCIDR":         subnet.CIDR,
		"totalIPConfigs":     totalIPConfigs,
		"availableAddresses": subnet.AvailableAddresses,
	}).Debug("Built final subnet object with accurate IP configuration count from all pages")

	return subnet, nil
}

// parseSubnetWithIPCount converts Azure subnet to Cilium format with custom IP config count
func parseSubnetWithIPCount(subnet *network.Subnet, ipConfigCount int) *ipamTypes.Subnet {
	s := &ipamTypes.Subnet{}
	if subnet.ID != nil {
		s.ID = *subnet.ID
	}
	if subnet.Name != nil {
		s.Name = *subnet.Name
	}

	if subnet.AddressPrefix != nil {
		c, err := cidr.ParseCIDR(*subnet.AddressPrefix)
		if err != nil {
			return nil
		}
		s.CIDR = c
		// Use the accurate IP config count from pagination
		s.AvailableAddresses = c.AvailableIPs() - ipConfigCount
	}

	return s
}

// emptyRequest creates an empty autorest request for authentication purposes
func emptyRequest() *http.Request {
	req, _ := http.NewRequest("GET", "", nil)
	return req
}

func generateIpConfigName() string {
	return "Cilium-" + rand.String(8)
}

// AssignPrivateIpAddressesVMSS assign a private IP to an interface attached to a VMSS instance
func (c *Client) AssignPrivateIpAddressesVMSS(ctx context.Context, instanceID, vmssName, subnetID, interfaceName string, addresses int) error {
	var netIfConfig *compute.VirtualMachineScaleSetNetworkConfiguration

	c.limiter.Limit(ctx, "VirtualMachineScaleSetVMs.Get")
	sinceStart := spanstat.Start()
	result, err := c.vmss.Get(ctx, c.resourceGroup, vmssName, instanceID, compute.InstanceViewTypesInstanceView)
	c.metricsAPI.ObserveAPICall("VirtualMachineScaleSetVMs.Get", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get VM %s from VMSS %s: %w", instanceID, vmssName, err)
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
	sinceStart = spanstat.Start()
	future, err := c.vmss.Update(ctx, c.resourceGroup, vmssName, instanceID, result)
	defer c.metricsAPI.ObserveAPICall("VirtualMachineScaleSetVMs.Update", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("unable to update virtualmachinescaleset: %w", err)
	}

	err = future.WaitForCompletionRef(ctx, c.vmss.Client)
	if err != nil {
		return fmt.Errorf("error while waiting for virtualmachinescalesets.Update() to complete: %w", err)
	}
	return nil
}

// AssignPrivateIpAddressesVM assign a private IP to an interface attached to a standalone instance
func (c *Client) AssignPrivateIpAddressesVM(ctx context.Context, subnetID, interfaceName string, addresses int) error {
	c.limiter.Limit(ctx, "Interfaces.Get")
	sinceStart := spanstat.Start()
	iface, err := c.interfaces.Get(ctx, c.resourceGroup, interfaceName, "")
	c.metricsAPI.ObserveAPICall("Interfaces.Get", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("failed to get standalone instance's interface %s: %w", interfaceName, err)
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
	sinceStart = spanstat.Start()
	future, err := c.interfaces.CreateOrUpdate(ctx, c.resourceGroup, interfaceName, iface)
	defer c.metricsAPI.ObserveAPICall("Interfaces.CreateOrUpdate", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return fmt.Errorf("unable to update interface %s: %w", interfaceName, err)
	}

	err = future.WaitForCompletionRef(ctx, c.interfaces.Client)
	if err != nil {
		return fmt.Errorf("error while waiting for interface.CreateOrUpdate() to complete for %s: %w", interfaceName, err)
	}

	return nil
}
