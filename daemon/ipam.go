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

package main

import (
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	ipamapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/node"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
)

type postIPAM struct {
	daemon *Daemon
}

// NewPostIPAMHandler creates a new postIPAM from the daemon.
func NewPostIPAMHandler(d *Daemon) ipamapi.PostIPAMHandler {
	return &postIPAM{daemon: d}
}

// Handle incoming requests address allocation requests for the daemon.
func (h *postIPAM) Handle(params ipamapi.PostIPAMParams) middleware.Responder {
	resp := &models.IPAMResponse{
		HostAddressing: node.GetNodeAddressing(),
		Address:        &models.AddressPair{},
	}

	ipv4, ipv6, err := ipam.AllocateNext(strings.ToLower(swag.StringValue(params.Family)))
	if err != nil {
		return api.Error(ipamapi.PostIPAMFailureCode, err)
	}

	if ipv4 != nil {
		resp.Address.IPV4 = ipv4.String()
	}

	if ipv6 != nil {
		resp.Address.IPV6 = ipv6.String()
	}

	return ipamapi.NewPostIPAMCreated().WithPayload(resp)
}

type postIPAMIP struct{}

// NewPostIPAMIPHandler creates a new postIPAM from the daemon.
func NewPostIPAMIPHandler(d *Daemon) ipamapi.PostIPAMIPHandler {
	return &postIPAMIP{}
}

// Handle incoming requests address allocation requests for the daemon.
func (h *postIPAMIP) Handle(params ipamapi.PostIPAMIPParams) middleware.Responder {
	if err := ipam.AllocateIPString(params.IP); err != nil {
		return api.Error(ipamapi.PostIPAMIPFailureCode, err)
	}

	return ipamapi.NewPostIPAMIPOK()
}

type deleteIPAMIP struct{}

// NewDeleteIPAMIPHandler handle incoming requests to delete addresses.
func NewDeleteIPAMIPHandler(d *Daemon) ipamapi.DeleteIPAMIPHandler {
	return &deleteIPAMIP{}
}

func (h *deleteIPAMIP) Handle(params ipamapi.DeleteIPAMIPParams) middleware.Responder {
	if err := ipam.ReleaseIPString(params.IP); err != nil {
		return api.Error(ipamapi.DeleteIPAMIPFailureCode, err)
	}

	return ipamapi.NewDeleteIPAMIPOK()
}

// DumpIPAM dumps in the form of a map, the list of
// reserved IPv4 and IPv6 addresses.
func (d *Daemon) DumpIPAM() *models.IPAMStatus {
	allocv4, allocv6 := ipam.Dump()
	return &models.IPAMStatus{
		IPV4: allocv4,
		IPV6: allocv6,
	}
}
