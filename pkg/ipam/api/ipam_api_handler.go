// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipamapi

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"

	"github.com/cilium/cilium/api/v1/models"
	ipamapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

type IpamDeleteIpamIPHandler struct {
	IPAM            *ipam.IPAM
	EndpointManager endpointmanager.EndpointManager
}

type IpamPostIpamHandler struct {
	Logger *slog.Logger
	IPAM   *ipam.IPAM
}

type IpamPostIpamIPHandler struct {
	IPAM *ipam.IPAM
}

func (r *IpamPostIpamHandler) Handle(params ipamapi.PostIpamParams) middleware.Responder {
	family := strings.ToLower(swag.StringValue(params.Family))
	owner := swag.StringValue(params.Owner)
	pool := ipam.Pool(swag.StringValue(params.Pool))
	var expirationTimeout time.Duration
	if swag.BoolValue(params.Expiration) {
		expirationTimeout = defaults.IPAMExpiration
	}
	ipv4Result, ipv6Result, err := r.IPAM.AllocateNextWithExpiration(family, owner, pool, expirationTimeout)
	if err != nil {
		return api.Error(ipamapi.PostIpamFailureCode, err)
	}

	resp := &models.IPAMResponse{
		HostAddressing: node.GetNodeAddressing(r.Logger),
		Address:        &models.AddressPair{},
	}

	if ipv4Result != nil {
		resp.Address.IPV4 = ipv4Result.IP.String()
		resp.Address.IPV4PoolName = ipv4Result.IPPoolName.String()
		resp.IPV4 = &models.IPAMAddressResponse{
			Cidrs:           ipv4Result.CIDRs,
			IP:              ipv4Result.IP.String(),
			MasterMac:       ipv4Result.PrimaryMAC,
			Gateway:         ipv4Result.GatewayIP,
			ExpirationUUID:  ipv4Result.ExpirationUUID,
			InterfaceNumber: ipv4Result.InterfaceNumber,
		}
	}

	if ipv6Result != nil {
		resp.Address.IPV6 = ipv6Result.IP.String()
		resp.Address.IPV6PoolName = ipv6Result.IPPoolName.String()
		resp.IPV6 = &models.IPAMAddressResponse{
			Cidrs:           ipv6Result.CIDRs,
			IP:              ipv6Result.IP.String(),
			MasterMac:       ipv6Result.PrimaryMAC,
			Gateway:         ipv6Result.GatewayIP,
			ExpirationUUID:  ipv6Result.ExpirationUUID,
			InterfaceNumber: ipv6Result.InterfaceNumber,
		}
	}

	return ipamapi.NewPostIpamCreated().WithPayload(resp)
}

// Handle incoming requests address allocation requests for the daemon.
func (r *IpamPostIpamIPHandler) Handle(params ipamapi.PostIpamIPParams) middleware.Responder {
	owner := swag.StringValue(params.Owner)
	pool := ipam.Pool(swag.StringValue(params.Pool))
	if err := r.IPAM.AllocateIPString(params.IP, owner, pool); err != nil {
		return api.Error(ipamapi.PostIpamIPFailureCode, err)
	}

	return ipamapi.NewPostIpamIPOK()
}

func (r *IpamDeleteIpamIPHandler) Handle(params ipamapi.DeleteIpamIPParams) middleware.Responder {
	// Release of an IP that is in use is not allowed
	if ep := r.EndpointManager.LookupIPv4(params.IP); ep != nil {
		return api.Error(ipamapi.DeleteIpamIPFailureCode, fmt.Errorf("IP is in use by endpoint %d", ep.ID))
	}
	if ep := r.EndpointManager.LookupIPv6(params.IP); ep != nil {
		return api.Error(ipamapi.DeleteIpamIPFailureCode, fmt.Errorf("IP is in use by endpoint %d", ep.ID))
	}

	ip := net.ParseIP(params.IP)
	if ip == nil {
		return api.Error(ipamapi.DeleteIpamIPInvalidCode, fmt.Errorf("Invalid IP address: %s", params.IP))
	}

	pool := ipam.Pool(swag.StringValue(params.Pool))
	if err := r.IPAM.ReleaseIP(ip, pool); err != nil {
		return api.Error(ipamapi.DeleteIpamIPFailureCode, err)
	}

	return ipamapi.NewDeleteIpamIPOK()
}
