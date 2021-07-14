// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

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
func (c *Client) IPAMAllocate(family, owner string, expiration bool) (*models.IPAMResponse, error) {
	params := ipam.NewPostIpamParams().WithTimeout(api.ClientTimeout)

	if family != "" {
		params.SetFamily(&family)
	}

	if owner != "" {
		params.SetOwner(&owner)
	}

	params.SetExpiration(&expiration)

	resp, err := c.Ipam.PostIpam(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// IPAMAllocateIP tries to allocate a particular IP address.
func (c *Client) IPAMAllocateIP(ip, owner string) error {
	params := ipam.NewPostIpamIPParams().WithIP(ip).WithOwner(&owner).WithTimeout(api.ClientTimeout)
	_, err := c.Ipam.PostIpamIP(params)
	return Hint(err)
}

// IPAMReleaseIP releases a IP address back to the pool.
func (c *Client) IPAMReleaseIP(ip string) error {
	params := ipam.NewDeleteIpamIPParams().WithIP(ip).WithTimeout(api.ClientTimeout)
	_, err := c.Ipam.DeleteIpamIP(params)
	return Hint(err)
}
