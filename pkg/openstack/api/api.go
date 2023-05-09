// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
	"github.com/gophercloud/gophercloud/pagination"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	eniTypes "github.com/cilium/cilium/pkg/openstack/eni/types"
	"github.com/cilium/cilium/pkg/openstack/types"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/api/helpers"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-openstack-operator")

const (
	NetworkID = "network_id"
	SubnetID  = "subnet_id"
	ProjectID = "project_id"

	VMDeviceOwner  = "compute:"
	PodDeviceOwner = "kubernetes:"
	CharSet        = "abcdefghijklmnopqrstuvwxyz0123456789"

	FakeAddresses = 100
)

var maxAttachRetries = wait.Backoff{
	Duration: 2500 * time.Millisecond,
	Factor:   1,
	Jitter:   0.1,
	Steps:    6,
	Cap:      0,
}

// Client an OpenStack API client
type Client struct {
	neutronV2  *gophercloud.ServiceClient
	novaV2     *gophercloud.ServiceClient
	keystoneV3 *gophercloud.ServiceClient

	limiter    *helpers.APILimiter
	metricsAPI MetricsAPI
	filters    map[string]string
}

// PortCreateOpts options to create port
type PortCreateOpts struct {
	Name          string
	NetworkID     string
	SubnetID      string
	IPAddress     string
	ProjectID     string
	SecurityGroup []string
	DeviceID      string
	DeviceOwner   string
	Tags          string
}

type FixedIPOpt struct {
	SubnetID        string `json:"subnet_id,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"`
	IPAddressSubstr string `json:"ip_address_subdir,omitempty"`
}
type FixedIPOpts []FixedIPOpt

// MetricsAPI represents the metrics maintained by the OpenStack API client
type MetricsAPI interface {
	helpers.MetricsAPI
	ObserveAPICall(call, status string, duration float64)
}

// NewClient create the client
func NewClient(metrics MetricsAPI, rateLimit float64, burst int, filters map[string]string) (*Client, error) {
	provider, err := newProviderClientOrDie(false)
	if err != nil {
		return nil, err
	}
	domainTokenProvider, err := newProviderClientOrDie(true)
	if err != nil {
		return nil, err
	}

	netV2, err := newNetworkV2ClientOrDie(provider)
	if err != nil {
		return nil, err
	}

	computeV2, err := newComputeV2ClientOrDie(provider)
	if err != nil {
		return nil, err
	}

	idenV3, err := newIdentityV3ClientOrDie(domainTokenProvider)
	if err != nil {
		return nil, err
	}

	return &Client{
		neutronV2:  netV2,
		novaV2:     computeV2,
		keystoneV3: idenV3,
		limiter:    helpers.NewAPILimiter(metrics, rateLimit, burst),
		metricsAPI: metrics,
		filters:    filters,
	}, nil
}

func newProviderClientOrDie(domainScope bool) (*gophercloud.ProviderClient, error) {
	opt, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		return nil, err
	}
	// with OS_PROJECT_NAME in env, AuthOptionsFromEnv return project scope token
	// which can not list projects, we need a domain scope token here
	if domainScope {
		opt.TenantName = ""
		opt.Scope = &gophercloud.AuthScope{
			DomainName: os.Getenv("OS_DOMAIN_NAME"),
		}
	}
	p, err := openstack.AuthenticatedClient(opt)
	if err != nil {
		return nil, err
	}
	p.HTTPClient = http.Client{
		Transport: http.DefaultTransport,
		Timeout:   time.Second * 60,
	}
	p.ReauthFunc = func() error {
		newprov, err := openstack.AuthenticatedClient(opt)
		if err != nil {
			return err
		}
		p.CopyTokenFrom(newprov)
		return nil
	}
	return p, nil
}

func newNetworkV2ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewNetworkV2(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Create a ComputeV2 service client using the AKSK provider
func newComputeV2ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewComputeV2(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

func newIdentityV3ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewIdentityV3(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// GetInstances returns the list of all instances including their ENIs as
// instanceMap
func (c *Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()
	var networkInterfaces []ports.Port
	var err error

	networkInterfaces, err = c.describeNetworkInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		if !strings.HasPrefix(iface.DeviceOwner, VMDeviceOwner) {
			continue
		}
		id, eni, err := parseENI(&iface, subnets)
		if err != nil {
			return nil, err
		}

		if id != "" {
			instances.Update(id, ipamTypes.InterfaceRevision{Resource: eni})
		}
	}

	return instances, nil
}

// GetVpcs retrieves and returns all Vpcs
func (c *Client) GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}
	vpcList, err := c.describeVpcs()
	if err != nil {
		return nil, err
	}

	for _, v := range vpcList {
		vpc := &ipamTypes.VirtualNetwork{ID: v.ID}
		vpcs[vpc.ID] = vpc
	}

	return vpcs, nil
}

// GetSubnets returns all subnets as a subnetMap
func (c *Client) GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error) {
	subnets := ipamTypes.SubnetMap{}
	subnetList, err := c.describeSubnets()
	if err != nil {
		return nil, err
	}

	for _, s := range subnetList {
		c, err := cidr.ParseCIDR(s.CIDR)
		if err != nil {
			continue
		}

		subnet := &ipamTypes.Subnet{
			ID:                 s.ID,
			VirtualNetworkID:   s.NetworkID,
			CIDR:               c,
			AvailableAddresses: FakeAddresses,
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

// GetSecurityGroups returns all security groups as a SecurityGroupMap
func (c *Client) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	securityGroups := types.SecurityGroupMap{}
	secGroupList, err := c.describeSecurityGroups()
	if err != nil {
		return securityGroups, err
	}

	for _, sg := range secGroupList {
		id := sg.ID

		securityGroup := &types.SecurityGroup{
			ID: id,
		}

		securityGroups[id] = securityGroup
	}

	return securityGroups, nil
}

// CreateNetworkInterface creates an ENI with the given parameters
func (c *Client) CreateNetworkInterface(ctx context.Context, subnetID, netID, instanceID string, groups []string) (string, *eniTypes.ENI, error) {

	opt := PortCreateOpts{
		Name:        fmt.Sprintf("cilium-vm-port-%s", randomString(10)),
		NetworkID:   netID,
		SubnetID:    subnetID,
		DeviceOwner: fmt.Sprintf(VMDeviceOwner+"%s", instanceID),
		ProjectID:   c.filters[ProjectID],
	}
	eni, err := c.createPort(opt)
	if err != nil {
		return "", nil, err
	}

	return eni.ID, eni, nil
}

// DeleteNetworkInterface deletes an ENI with the specified ID
func (c *Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	r := ports.Delete(c.neutronV2, eniID)
	return r.ExtractErr()
}

// AttachNetworkInterface attaches a previously created ENI to an instanceq
func (c *Client) AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error {

	createOpts := attachinterfaces.CreateOpts{
		PortID: eniID,
	}
	_, err := attachinterfaces.Create(c.novaV2, instanceID, createOpts).Extract()
	if err != nil {
		return err
	}

	return nil
}

// AssignPrivateIPAddresses assigns the specified number of secondary IP
// return allocated IPs
func (c *Client) AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error) {

	port, err := c.getPort(eniID)
	if err != nil {
		log.Errorf("Failed to get port: %s, with error %s", eniID, err)
		return nil, err
	}

	var addresses []string
	allowedAddressPairs := port.AllowedAddressPairs

	for i := 0; i < toAllocate; i++ {
		opt := PortCreateOpts{
			Name:        fmt.Sprintf("cilium-pod-port-%s", randomString(10)),
			NetworkID:   port.NetworkID,
			SubnetID:    port.FixedIPs[0].SubnetID,
			DeviceOwner: fmt.Sprintf(PodDeviceOwner+"%s", eniID),
			ProjectID:   c.filters[ProjectID],
		}
		p, err := c.createPort(opt)
		if err != nil {
			log.Errorf("Failed to create port with error %s", err)
			return addresses, err
		}

		addresses = append(addresses, p.IP)
		allowedAddressPairs = append(allowedAddressPairs, ports.AddressPair{IPAddress: p.IP})

		err = c.updatePortAllowedAddressPairs(eniID, allowedAddressPairs)
		if err != nil {
			log.Errorf("Failed to update port allowed-address-pairs with error: %+v", err)
			err = c.deletePort(p.ID)
			if err != nil {
				log.Errorf("Failed to rollback to delete port with error: %+v", err)
			}
			return addresses, err
		}
	}

	return addresses, nil
}

// UnassignPrivateIPAddresses unassign specified IP addresses from ENI
// should not provide Primary IP
func (c *Client) UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) error {
	log.Errorf("Do Unassign ip addresses for nic %s, count is %s", eniID, addresses)
	return nil
}

// updatePortAllowedAddressPairs to assign secondary ip address
func (c Client) updatePortAllowedAddressPairs(eniID string, pairs []ports.AddressPair) error {
	opts := ports.UpdateOpts{
		AllowedAddressPairs: &pairs,
	}
	_, err := ports.Update(c.neutronV2, eniID, opts).Extract()
	if err != nil {
		return err
	}
	return nil
}

// get neutron port
func (c Client) getPort(id string) (*ports.Port, error) {
	return ports.Get(c.neutronV2, id).Extract()
}

// create neturon port for both CreateNetworkInterface and AssignIpAddress
func (c *Client) createPort(opt PortCreateOpts) (*eniTypes.ENI, error) {

	copts := ports.CreateOpts{
		Name:        opt.Name,
		NetworkID:   opt.NetworkID,
		DeviceOwner: opt.DeviceOwner,
		ProjectID:   opt.ProjectID,
		FixedIPs: FixedIPOpts{
			{
				SubnetID:  opt.SubnetID,
				IPAddress: opt.IPAddress,
			},
		},
	}

	port, err := ports.Create(c.neutronV2, copts).Extract()
	if err != nil {
		return nil, err
	}

	eni := eniTypes.ENI{
		ID:             port.ID,
		IP:             port.FixedIPs[0].IPAddress,
		MAC:            port.MACAddress,
		SecurityGroups: port.SecurityGroups,
		VPC:            eniTypes.VPC{ID: port.NetworkID},
		Subnet:         eniTypes.Subnet{ID: opt.SubnetID},
	}

	return &eni, nil
}

func (c *Client) deletePort(id string) error {
	r := ports.Delete(c.neutronV2, id)
	return r.ExtractErr()
}

// parseENI parses a ecs.NetworkInterface as returned by the ecs service API,
// converts it into a eniTypes.ENI object
func parseENI(port *ports.Port, subnets ipamTypes.SubnetMap) (instanceID string, eni *eniTypes.ENI, err error) {

	var eniType string
	if strings.HasPrefix(port.DeviceOwner, VMDeviceOwner) {
		eniType = eniTypes.ENITypePrimary
	} else if strings.HasPrefix(port.DeviceOwner, PodDeviceOwner) {
		eniType = eniTypes.ENITypeSecondary
	}

	subnetID := port.FixedIPs[0].SubnetID
	eni = &eniTypes.ENI{
		ID:             port.ID,
		IP:             port.FixedIPs[0].IPAddress,
		MAC:            port.MACAddress,
		SecurityGroups: port.SecurityGroups,
		VPC:            eniTypes.VPC{ID: port.NetworkID},
		Subnet:         eniTypes.Subnet{ID: subnetID},
		Type:           eniType,
	}

	subnet, ok := subnets[subnetID]
	if ok && subnet.CIDR != nil {
		eni.Subnet.CIDR = subnet.CIDR.String()
	}

	var ipsets []eniTypes.PrivateIPSet
	for _, pairs := range port.AllowedAddressPairs {
		if validIPAddress(pairs.IPAddress, subnet.CIDR.IPNet) {
			ipsets = append(ipsets, eniTypes.PrivateIPSet{
				IpAddress: pairs.IPAddress,
			})
		}
	}
	eni.SecondaryIPSets = ipsets

	return port.DeviceID, eni, nil
}

func validIPAddress(ipStr string, cidr *net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// describeNetworkInterfaces lists all ENIs
func (c *Client) describeNetworkInterfaces() ([]ports.Port, error) {
	var result []ports.Port
	var err error

	opts := ports.ListOpts{
		NetworkID: c.filters[NetworkID],
		ProjectID: c.filters[ProjectID],
		FixedIPs: []ports.FixedIPOpts{
			{
				SubnetID: c.filters[SubnetID],
			},
		},
	}

	err = ports.List(c.neutronV2, opts).EachPage(func(page pagination.Page) (bool, error) {
		result, err = ports.ExtractPorts(page)
		if err != nil {
			return false, err
		}

		return true, nil
	})

	return result, nil
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs() ([]networks.Network, error) {
	opts := networks.ListOpts{
		ProjectID: c.filters[ProjectID],
	}
	pages, _ := networks.List(c.neutronV2, opts).AllPages()
	allNetworks, _ := networks.ExtractNetworks(pages)
	return allNetworks, nil
}

// describeSubnets lists all subnets
func (c *Client) describeSubnets() ([]subnets.Subnet, error) {
	opts := subnets.ListOpts{
		ProjectID: c.filters[ProjectID],
		NetworkID: c.filters[NetworkID],
	}
	pages, _ := subnets.List(c.neutronV2, opts).AllPages()
	allSubnets, _ := subnets.ExtractSubnets(pages)
	return allSubnets, nil
}

func (c *Client) describeSecurityGroups() ([]groups.SecGroup, error) {
	opts := groups.ListOpts{
		ProjectID: c.filters[ProjectID],
	}
	pages, _ := groups.List(c.neutronV2, opts).AllPages()
	allSecGroups, _ := groups.ExtractGroups(pages)
	return allSecGroups, nil
}

func randomString(length int) string {
	rand.Seed(time.Now().UnixNano())

	b := make([]byte, length)
	for i := range b {
		b[i] = CharSet[rand.Intn(len(CharSet))]
	}
	return string(b)
}
