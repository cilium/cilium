// Copyright 2019-2021 Authors of Cilium
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

package ipam

import (
	"fmt"
	"net"

	ipamapi "github.com/cilium/cilium/api/v1/client/ipam"
	"github.com/cilium/cilium/pkg/client"

	"github.com/go-openapi/strfmt"
)

var _ Allocator = &External{}

func newExternal(address string, family Family) (Allocator, error) {
	tr, err := client.NewTransport(address)
	if err != nil {
		return nil, err
	}

	return &External{
		family: string(family),
		client: ipamapi.New(tr, strfmt.Default),
	}, nil
}

type External struct {
	family string
	client ipamapi.ClientService
}

func (e *External) Allocate(ip net.IP, owner string) (*AllocationResult, error) {
	body := ipamapi.NewPostIpamIPParams()
	body.SetIP(ip.String())
	body.SetOwner(&owner)

	_, err := e.client.PostIpamIP(body)
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (e *External) AllocateWithoutSyncUpstream(ip net.IP, owner string) (*AllocationResult, error) {
	return e.Allocate(ip, owner)
}

func (e *External) Release(ip net.IP) error {
	body := ipamapi.NewDeleteIpamIPParams()
	body.SetIP(ip.String())

	_, err := e.client.DeleteIpamIP(body)
	if err != nil {
		return err
	}

	return nil
}

func (e *External) AllocateNext(owner string) (*AllocationResult, error) {
	body := ipamapi.NewPostIpamParams()
	body.SetFamily(&e.family)
	body.SetOwner(&owner)

	resp, err := e.client.PostIpam(body)
	if err != nil {
		return nil, err
	}

	if e.family == string(IPv4) {
		return &AllocationResult{IP: net.ParseIP(resp.GetPayload().IPV4.IP)}, nil
	}

	if e.family == string(IPv6) {
		return &AllocationResult{IP: net.ParseIP(resp.GetPayload().IPV6.IP)}, nil
	}

	panic(fmt.Errorf("unreachable, unsupported ip family: %s", e.family))
}

func (e *External) AllocateNextWithoutSyncUpstream(owner string) (*AllocationResult, error) {
	return e.AllocateNext(owner)
}

func (e *External) Dump() (map[string]string, string) {
	// TODO
	return nil, ""
}

func (e *External) RestoreFinished() {
	return
}
