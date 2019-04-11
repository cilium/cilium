// Copyright 2016-2017 Authors of Cilium
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
func (c *Client) IPAMAllocate(family, owner string) (*models.IPAMResponse, error) {
	params := ipam.NewPostIPAMParams().WithTimeout(api.ClientTimeout)

	if family != "" {
		params.SetFamily(&family)
	}

	if owner != "" {
		params.SetOwner(&owner)
	}

	resp, err := c.IPAM.PostIPAM(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// IPAMAllocateIP tries to allocate a particular IP address.
func (c *Client) IPAMAllocateIP(ip, owner string) error {
	params := ipam.NewPostIPAMIPParams().WithIP(ip).WithOwner(&owner).WithTimeout(api.ClientTimeout)
	_, err := c.IPAM.PostIPAMIP(params)
	return Hint(err)
}

// IPAMReleaseIP releases a IP address back to the pool.
func (c *Client) IPAMReleaseIP(ip string) error {
	params := ipam.NewDeleteIPAMIPParams().WithIP(ip).WithTimeout(api.ClientTimeout)
	_, err := c.IPAM.DeleteIPAMIP(params)
	return Hint(err)
}
