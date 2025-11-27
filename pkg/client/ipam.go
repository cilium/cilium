// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/ipam"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

const (
	AddressFamilyIPv6 = "ipv6"
	AddressFamilyIPv4 = "ipv4"
)

// IPAMAllocate allocates an IP address out of address family specific pool.
func (c *Client) IPAMAllocate(family, owner, pool string, expiration bool) (*models.IPAMResponse, error) {
	params := ipam.NewPostIpamParams().WithTimeout(api.ClientTimeout)

	if family != "" {
		params.SetFamily(&family)
	}
	if owner != "" {
		params.SetOwner(&owner)
	}
	if pool != "" {
		params.SetPool(&pool)
	}
	params.SetExpiration(&expiration)

	resp, err := c.Ipam.PostIpam(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// IPAMAllocateIP tries to allocate a particular IP address.
func (c *Client) IPAMAllocateIP(ip, owner, pool string) error {
	params := ipam.NewPostIpamIPParams().WithIP(ip).WithOwner(&owner).WithTimeout(api.ClientTimeout)
	if pool != "" {
		params.SetPool(&pool)
	}
	_, err := c.Ipam.PostIpamIP(params)
	return Hint(err)
}

// IPAMReleaseIP releases a IP address back to the pool.
func (c *Client) IPAMReleaseIP(ip, pool string) error {
	params := ipam.NewDeleteIpamIPParams().WithIP(ip).WithTimeout(api.ClientTimeout)
	if pool != "" {
		params.SetPool(&pool)
	}
	_, err := c.Ipam.DeleteIpamIP(params)
	return Hint(err)
}

// IPAMAllocateSpecificIP allocates a specific IP address and returns the full IPAM response.
// This is similar to IPAMAllocateIP but returns the IPAMResponse for consistency with IPAMAllocate.
func (c *Client) IPAMAllocateSpecificIP(ip, owner, pool string) (*models.IPAMResponse, error) {
	// First allocate the specific IP
	params := ipam.NewPostIpamIPParams().WithIP(ip).WithOwner(&owner).WithTimeout(api.ClientTimeout)
	if pool != "" {
		params.SetPool(&pool)
	}

	_, err := c.Ipam.PostIpamIP(params)
	if err != nil {
		return nil, Hint(err)
	}

	// Get the daemon configuration to obtain host addressing
	configResult, err := c.ConfigGet()
	if err != nil {
		return nil, Hint(err)
	}

	// Build the response similar to IPAMAllocate
	result := &models.IPAMResponse{
		Address: &models.AddressPair{},
	}

	// Set host addressing from daemon config
	if configResult != nil && configResult.Status != nil {
		result.HostAddressing = configResult.Status.Addressing
	}

	// Determine if it's IPv4 or IPv6 and set the address
	if isIPv4(ip) {
		result.Address.IPV4 = ip
		result.Address.IPV4PoolName = pool
		// Also add IPV4 details if available
		if result.HostAddressing != nil && result.HostAddressing.IPV4 != nil {
			result.IPV4 = &models.IPAMAddressResponse{
				IP:      ip,
				Gateway: result.HostAddressing.IPV4.IP,
			}
		}
	} else {
		result.Address.IPV6 = ip
		result.Address.IPV6PoolName = pool
		// Also add IPV6 details if available
		if result.HostAddressing != nil && result.HostAddressing.IPV6 != nil {
			result.IPV6 = &models.IPAMAddressResponse{
				IP:      ip,
				Gateway: result.HostAddressing.IPV6.IP,
			}
		}
	}

	return result, nil
}

// isIPv4 checks if the IP string is an IPv4 address
func isIPv4(ip string) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' {
			return true
		}
		if ip[i] == ':' {
			return false
		}
	}
	return false
}
