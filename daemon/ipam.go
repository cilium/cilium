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
	"math/big"
	"net"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/nodeaddress"

	log "github.com/Sirupsen/logrus"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	k8sAPI "k8s.io/kubernetes/pkg/api"
)

// AllocateIP allocates a IP address.
func (d *Daemon) AllocateIP(ip net.IP) *apierror.APIError {
	d.ipamConf.AllocatorMutex.Lock()
	defer d.ipamConf.AllocatorMutex.Unlock()

	if ip.To4() != nil {
		if d.ipamConf.IPv4Allocator == nil {
			return apierror.New(ipam.PostIPAMIPDisabledCode, "IPv4 allocation disabled")
		}

		if err := d.ipamConf.IPv4Allocator.Allocate(ip); err != nil {
			return apierror.Error(ipam.PostIPAMIPFailureCode, err)
		}
	} else {
		if d.ipamConf.IPv6Allocator == nil {
			return apierror.New(ipam.PostIPAMIPDisabledCode, "IPv6 allocation disabled")
		}

		if err := d.ipamConf.IPv6Allocator.Allocate(ip); err != nil {
			return apierror.Error(ipam.PostIPAMIPFailureCode, err)
		}
	}

	return nil
}

func (d *Daemon) allocateIP(ipAddr string) *apierror.APIError {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return apierror.New(ipam.PostIPAMIPInvalidCode, "Invalid IP address: %s", ipAddr)
	}
	return d.AllocateIP(ip)
}

// ReleaseIP release a IP address.
func (d *Daemon) ReleaseIP(ip net.IP) *apierror.APIError {
	d.ipamConf.AllocatorMutex.Lock()
	defer d.ipamConf.AllocatorMutex.Unlock()

	if ip.To4() != nil {
		if d.ipamConf.IPv4Allocator == nil {
			return apierror.New(ipam.DeleteIPAMIPDisabledCode, "IPv4 allocation disabled")
		}

		if err := d.ipamConf.IPv4Allocator.Release(ip); err != nil {
			return apierror.Error(ipam.DeleteIPAMIPFailureCode, err)
		}
	} else {
		if d.ipamConf.IPv6Allocator == nil {
			return apierror.New(ipam.DeleteIPAMIPDisabledCode, "IPv6 allocation disabled")
		}

		if err := d.ipamConf.IPv6Allocator.Release(ip); err != nil {
			return apierror.Error(ipam.DeleteIPAMIPFailureCode, err)
		}
	}

	return nil
}

func (d *Daemon) releaseIP(ipAddr string) *apierror.APIError {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return apierror.New(ipam.DeleteIPAMIPInvalidCode, "Invalid IP address: %s", ipAddr)
	}
	return d.ReleaseIP(ip)
}

type postIPAM struct {
	daemon *Daemon
}

// NewPostIPAMHandler creates a new postIPAM from the daemon.
func NewPostIPAMHandler(d *Daemon) ipam.PostIPAMHandler {
	return &postIPAM{daemon: d}
}

// Handle incoming requests address allocation requests for the daemon.
func (h *postIPAM) Handle(params ipam.PostIPAMParams) middleware.Responder {
	d := h.daemon
	d.ipamConf.AllocatorMutex.Lock()
	defer d.ipamConf.AllocatorMutex.Unlock()

	resp := &models.IPAM{
		HostAddressing: d.getNodeAddressing(),
		Endpoint:       &models.EndpointAddressing{},
	}

	family := strings.ToLower(swag.StringValue(params.Family))

	log.Debugf("%+v %+v\n", family, d.ipamConf.IPv4Allocator)

	if (family == "ipv6" || family == "") && d.ipamConf.IPv6Allocator != nil {
		ipConf, err := d.ipamConf.IPv6Allocator.AllocateNext()
		if err != nil {
			return apierror.Error(ipam.PostIPAMFailureCode, err)
		}

		resp.Endpoint.IPV6 = ipConf.String()
	}

	if (family == "ipv4" || family == "") && d.ipamConf.IPv4Allocator != nil {
		ipConf, err := d.ipamConf.IPv4Allocator.AllocateNext()
		if err != nil {
			return apierror.Error(ipam.PostIPAMFailureCode, err)
		}

		resp.Endpoint.IPV4 = ipConf.String()
	}

	return ipam.NewPostIPAMCreated().WithPayload(resp)
}

type postIPAMIP struct {
	daemon *Daemon
}

// NewPostIPAMIPHandler creates a new postIPAM from the daemon.
func NewPostIPAMIPHandler(d *Daemon) ipam.PostIPAMIPHandler {
	return &postIPAMIP{daemon: d}
}

// Handle incoming requests address allocation requests for the daemon.
func (h *postIPAMIP) Handle(params ipam.PostIPAMIPParams) middleware.Responder {
	if err := h.daemon.allocateIP(params.IP); err != nil {
		return err
	}

	return ipam.NewPostIPAMIPOK()
}

type deleteIPAMIP struct {
	d *Daemon
}

// NewDeleteIPAMIPHandler handle incoming requests to delete addresses.
func NewDeleteIPAMIPHandler(d *Daemon) ipam.DeleteIPAMIPHandler {
	return &deleteIPAMIP{d: d}
}

func (h *deleteIPAMIP) Handle(params ipam.DeleteIPAMIPParams) middleware.Responder {
	if err := h.d.releaseIP(params.IP); err != nil {
		return err
	}

	return ipam.NewDeleteIPAMIPOK()
}

// DumpIPAM dumps in the form of a map, and only if debug is enabled, the list of
// reserved IPv4 and IPv6 addresses.
func (d *Daemon) DumpIPAM() *models.IPAMStatus {
	if !d.conf.Opts.IsEnabled(endpoint.OptionDebug) {
		return nil
	}

	d.ipamConf.AllocatorMutex.RLock()
	defer d.ipamConf.AllocatorMutex.RUnlock()

	allocv4 := []string{}
	if !d.conf.IPv4Disabled {
		ralv4 := k8sAPI.RangeAllocation{}
		d.ipamConf.IPv4Allocator.Snapshot(&ralv4)
		origIP := big.NewInt(0).SetBytes(nodeaddress.GetIPv4AllocRange().IP)
		v4Bits := big.NewInt(0).SetBytes(ralv4.Data)
		for i := 0; i < v4Bits.BitLen(); i++ {
			if v4Bits.Bit(i) != 0 {
				allocv4 = append(allocv4, net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String())
			}
		}
	}

	allocv6 := []string{}
	ralv6 := k8sAPI.RangeAllocation{}
	d.ipamConf.IPv6Allocator.Snapshot(&ralv6)
	origIP := big.NewInt(0).SetBytes(nodeaddress.GetIPv6AllocRange().IP)
	v6Bits := big.NewInt(0).SetBytes(ralv6.Data)
	for i := 0; i < v6Bits.BitLen(); i++ {
		if v6Bits.Bit(i) != 0 {
			allocv6 = append(allocv6, net.IP(big.NewInt(0).Add(origIP, big.NewInt(int64(uint(i+1)))).Bytes()).String())
		}
	}

	return &models.IPAMStatus{
		IPV4: allocv4,
		IPV6: allocv6,
	}
}
