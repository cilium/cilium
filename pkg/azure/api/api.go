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

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/aws/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/spanstat"

	"golang.org/x/time/rate"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-05-01/network"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

const (
	userAgent = "cilium"
)

// Client represents an EC2 API client
type Client struct {
	interfaces network.InterfacesClient
	limiter    *rate.Limiter
	metricsAPI metricsAPI
}

type metricsAPI interface {
	ObserveAzureAPICall(call, status string, duration float64)
	ObserveAzureRateLimit(operation string, duration time.Duration)
}

// NewClient returns a new EC2 client
func NewClient(subscriptionID string, metrics metricsAPI, rateLimit float64, burst int) (*Client, error) {
	c := &Client{
		interfaces:     network.NewInterfacesClient(subscriptionID),
		vitualnetworks: network.NewVirtualNetworksClient(subscriptionID),
		metricsAPI:     metrics,
		limiter:        rate.NewLimiter(rate.Limit(rateLimit), burst),
	}

	// Authorizer based on environment variables
	authorizer, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return nil, err
	}

	c.interfaces.Authorizer = authorizer
	c.interfaces.AddToUserAgent(userAgent)
	c.virtualnetworks.Authorizer = authorizer
	c.virtualnetworks.AddToUserAgent(userAgent)

	return c, nil
}

// deriveStatus returns a status string
func deriveStatus(err error) string {
	if err != nil {
		return "Failed"
	}

	return "OK"
}

func (c *Client) rateLimit(ctx context.Context, operation string) {
	r := c.limiter.Reserve()
	if delay := r.Delay(); delay != time.Duration(0) && delay != rate.InfDuration {
		c.metricsAPI.ObserveAzureRateLimit(operation, delay)
		c.limiter.Wait(ctx)
	}
}

// describeNetworkInterfaces lists all Azure Interfaces
func (c *Client) describeNetworkInterfaces(ctx context.Context) ([]network.Interface, error) {
	var networkInterfaces []network.Interface

	c.rateLimit(ctx, "Interfaces.ListAll")
	sinceStart := spanstat.Start()
	result, err := c.interfaces.ListAllComplete(ctx)
	c.metricsAPI.ObserveAzureAPICall("Interfaces.ListAll", deriveStatus(err), sinceStart.Seconds())

	for result.NotDone() {
		if err != nil {
			return nil, err
		}

		networkInterfaces = append(networkInterfaces, result.Value())
		err = list.Next()
	}

	return networkInterfaces, nil
}

// parseInterfaces parses a network.Interface as returned by the Azure API
// converts it into a v2.AzureInterface
func parseInterface(iface *network.Interface) (instanceID string, i *v2.AzureInterface) {
	i = &v2.AzureInterface{Addresses: []string{}}

	if iface.VirtualMachine != nil && iface.VirtualMachine.ID != nil {
		instanceID = *iface.VirtualMachine.ID
	}

	if iface.MacAddress != nil {
		i.MAC = *iface.MacAddress
	}

	if iface.ID != nil {
		i.ID = *iface.ID
	}

	if iface.NetworkSecurityGroup != nil {
		if iface.NetworkSecurityGroup.ID != nil {
			i.SecurityGroup = *iface.NetworkSecurityGroup.ID
		}
	}

	for _, ip := range iface.IPConfigurations {
		if ip.PrivateIPAddress != nil {
			i.Addresses = append(i.Addresses, *ip.PrivateIPAddress)
		}
	}

	return
}

// GetInstances returns the list of all instances including their ENIs as
// instanceMap
func (c *Client) GetInstances(ctx context.Context) (types.InstanceMap, error) {
	instances := types.InstanceMap{}

	networkInterfaces, err := c.describeNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		id, azureInterface, err := parseInterface(iface, vnets)
		if err != nil {
			return nil, err
		}

		if id != "" {
			instances.Add(id, azureInterface)
		}
	}

	return instances, nil
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs(ctx context.Context) ([]network.VirtualNetwork, error) {
	var vpcs []network.VirtualNetwork

	c.rateLimit(ctx, "VirtualNetworks.List")

	sinceStart := spanstat.Start()
	result, err := c.virtualnetworks.ListAllComplete(ctx)
	c.metricsAPI.ObserveAzureAPICall("Interfaces.ListAll", deriveStatus(err), sinceStart.Seconds())

	for result.NotDone() {
		if err != nil {
			return nil, err
		}

		vpcs = append(vpcs, result.Value())
		err = list.Next()
	}

	return vpcs, nil
}

// GetVpcs retrieves and returns all Vpcs
func (c *Client) GetVpcs(ctx context.Context) (ipam.VirtualNetworkMap, error) {
	vpcs := ipam.VirtualNetworkMap{}

	vpcList, err := c.describeVpcs(ctx)
	if err != nil {
		return nil, err
	}

	for _, v := range vpcList {
		vpc := &ipam.VirtualNetwork{ID: *v.ID}
		vpcs[vpc.ID] = vpc
	}

	return vpcs, nil
}
