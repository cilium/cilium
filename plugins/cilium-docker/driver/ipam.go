// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/docker/libnetwork/ipams/remote/api"

	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	PoolIPv4 = "CiliumPoolv4"
	PoolIPv6 = "CiliumPoolv6"
)

func (driver *driver) ipamCapabilities(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(&api.GetCapabilityResponse{})
	if err != nil {
		log.WithError(err).Fatal("capabilities encode")
		sendError(w, "encode error", http.StatusInternalServerError)
		return
	}
	log.Debug("IPAM capabilities exchange complete")
}

func (driver *driver) getDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	log.Debug("GetDefaultAddressSpaces Called")

	resp := &api.GetAddressSpacesResponse{
		LocalDefaultAddressSpace:  "CiliumLocal",
		GlobalDefaultAddressSpace: "CiliumGlobal",
	}

	log.WithField(logfields.Response, logfields.Repr(resp)).Debug("Get Default Address Spaces response")
	objectResponse(w, resp)
}

func (driver *driver) getPoolResponse(req *api.RequestPoolRequest) *api.RequestPoolResponse {
	addr := driver.conf.Addressing
	if req.V6 == false {
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
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.WithField(logfields.Request, logfields.Repr(&req)).Debug("Request Pool request")
	resp := driver.getPoolResponse(&req)
	log.WithField(logfields.Response, logfields.Repr(resp)).Debug("Request Pool response")
	objectResponse(w, resp)
}

func (driver *driver) releasePool(w http.ResponseWriter, r *http.Request) {
	var release api.ReleasePoolRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.WithField(logfields.Request, logfields.Repr(&release)).Debug("Release Pool request")

	emptyResponse(w)
}

func (driver *driver) requestAddress(w http.ResponseWriter, r *http.Request) {
	var request api.RequestAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.WithField(logfields.Request, logfields.Repr(&request)).Debug("Request Address request")

	family := client.AddressFamilyIPv6 // Default
	switch request.PoolID {
	case PoolIPv4:
		family = client.AddressFamilyIPv4
	case PoolIPv6:
		family = client.AddressFamilyIPv6
	}

	ipam, err := driver.client.IPAMAllocate(family, "docker-ipam", "", false)
	if err != nil {
		sendError(w, fmt.Sprintf("Could not allocate IP address: %s", err), http.StatusBadRequest)
		return
	}

	// The host addressing may have changed due to a daemon restart, update it
	driver.updateRoutes(ipam.HostAddressing)

	addr := ipam.Address
	if addr == nil {
		sendError(w, "No IP addressing provided", http.StatusBadRequest)
		return
	}

	resp := &api.RequestAddressResponse{}
	if addr.IPV6 != "" {
		if family != client.AddressFamilyIPv6 {
			sendError(w, "Requested IPv4, received IPv6 address", http.StatusInternalServerError)
		}
		resp.Address = addr.IPV6 + "/128"
	} else if addr.IPV4 != "" {
		if family != client.AddressFamilyIPv4 {
			sendError(w, "Requested IPv6, received IPv4 address", http.StatusInternalServerError)
		}
		resp.Address = addr.IPV4 + "/32"
	}

	log.WithField(logfields.Response, logfields.Repr(resp)).Debug("Request Address response")
	objectResponse(w, resp)
}

func (driver *driver) releaseAddress(w http.ResponseWriter, r *http.Request) {
	var release api.ReleaseAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.WithField(logfields.Request, logfields.Repr(&release)).Debug("Release Address request")
	if err := driver.client.IPAMReleaseIP(release.Address, ""); err != nil {
		sendError(w, fmt.Sprintf("Could not release IP address: %s", err), http.StatusBadRequest)
		return
	}

	emptyResponse(w)
}
