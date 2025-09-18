// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/docker/libnetwork/ipams/remote/api"

	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	PoolIPv4 = "CiliumPoolv4"
	PoolIPv6 = "CiliumPoolv6"
)

func (driver *driver) ipamCapabilities(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(&api.GetCapabilityResponse{})
	if err != nil {
		logging.Fatal(driver.logger, "capabilities encode", logfields.Error, err)
		sendError(driver.logger, w, "encode error", http.StatusInternalServerError)
		return
	}
	driver.logger.Debug("IPAM capabilities exchange complete")
}

func (driver *driver) getDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	driver.logger.Debug("GetDefaultAddressSpaces Called")

	resp := &api.GetAddressSpacesResponse{
		LocalDefaultAddressSpace:  "CiliumLocal",
		GlobalDefaultAddressSpace: "CiliumGlobal",
	}

	driver.logger.Debug("Get Default Address Spaces response", logfields.Response, resp)
	objectResponse(driver.logger, w, resp)
}

func (driver *driver) getPoolResponse(req *api.RequestPoolRequest) *api.RequestPoolResponse {
	addr := driver.conf.Addressing
	if !req.V6 {
		return &api.RequestPoolResponse{
			PoolID: PoolIPv4,
			Pool:   "0.0.0.0/0",
			Data: map[string]string{
				"com.docker.network.gateway": addr.IPV4.IP + "/32",
			},
		}
	}

	return &api.RequestPoolResponse{
		PoolID: PoolIPv6,
		Pool:   addr.IPV6.AllocRange,
		Data: map[string]string{
			"com.docker.network.gateway": addr.IPV6.IP + "/128",
		},
	}
}

func (driver *driver) requestPool(w http.ResponseWriter, r *http.Request) {
	var req api.RequestPoolRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(driver.logger, w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	driver.logger.Debug("Request Pool request", logfields.Request, req)
	resp := driver.getPoolResponse(&req)
	driver.logger.Debug("Request Pool response", logfields.Response, resp)
	objectResponse(driver.logger, w, resp)
}

func (driver *driver) releasePool(w http.ResponseWriter, r *http.Request) {
	var release api.ReleasePoolRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(driver.logger, w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	driver.logger.Debug("Release Pool request", logfields.Request, release)

	emptyResponse(w)
}

func (driver *driver) requestAddress(w http.ResponseWriter, r *http.Request) {
	var request api.RequestAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		sendError(driver.logger, w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	driver.logger.Debug("Request Address request", logfields.Request, request)

	family := client.AddressFamilyIPv6 // Default
	switch request.PoolID {
	case PoolIPv4:
		family = client.AddressFamilyIPv4
	case PoolIPv6:
		family = client.AddressFamilyIPv6
	}

	ipam, err := driver.client.IPAMAllocate(family, "docker-ipam", "", false)
	if err != nil {
		sendError(driver.logger, w, fmt.Sprintf("Could not allocate IP address: %s", err), http.StatusBadRequest)
		return
	}

	// The host addressing may have changed due to a daemon restart, update it
	driver.updateRoutes(ipam.HostAddressing)

	addr := ipam.Address
	if addr == nil {
		sendError(driver.logger, w, "No IP addressing provided", http.StatusBadRequest)
		return
	}

	resp := &api.RequestAddressResponse{}
	if addr.IPV6 != "" {
		if family != client.AddressFamilyIPv6 {
			sendError(driver.logger, w, "Requested IPv4, received IPv6 address", http.StatusInternalServerError)
		}
		resp.Address = addr.IPV6 + "/128"
	} else if addr.IPV4 != "" {
		if family != client.AddressFamilyIPv4 {
			sendError(driver.logger, w, "Requested IPv6, received IPv4 address", http.StatusInternalServerError)
		}
		resp.Address = addr.IPV4 + "/32"
	}

	driver.logger.Debug("Request Address response", logfields.Response, resp)
	objectResponse(driver.logger, w, resp)
}

func (driver *driver) releaseAddress(w http.ResponseWriter, r *http.Request) {
	var release api.ReleaseAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(driver.logger, w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	driver.logger.Debug("Release Address request", logfields.Request, release)
	if err := driver.client.IPAMReleaseIP(release.Address, ""); err != nil {
		sendError(driver.logger, w, fmt.Sprintf("Could not release IP address: %s", err), http.StatusBadRequest)
		return
	}

	emptyResponse(w)
}
