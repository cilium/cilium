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
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipam"

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
	resp := &models.IPAM{
		HostAddressing: h.daemon.getNodeAddressing(),
		Endpoint:       &models.EndpointAddressing{},
	}

	ipv4, ipv6, err := ipam.AllocateNext(strings.ToLower(swag.StringValue(params.Family)))
	if err != nil {
		return apierror.Error(ipamapi.PostIPAMFailureCode, err)
	}

	if ipv4 != nil {
		resp.Endpoint.IPV4 = ipv4.String()
	}

	if ipv6 != nil {
		resp.Endpoint.IPV6 = ipv6.String()
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
		return apierror.Error(ipamapi.PostIPAMIPFailureCode, err)
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
		return apierror.Error(ipamapi.DeleteIPAMIPFailureCode, err)
	}

	return ipamapi.NewDeleteIPAMIPOK()
}

// DumpIPAM dumps in the form of a map, and only if debug is enabled, the list of
// reserved IPv4 and IPv6 addresses.
func (d *Daemon) DumpIPAM() *models.IPAMStatus {
	if !d.conf.Opts.IsEnabled(endpoint.OptionDebug) {
		return nil
	}

	allocv4, allocv6 := ipam.Dump()
	return &models.IPAMStatus{
		IPV4: allocv4,
		IPV6: allocv6,
	}
}
