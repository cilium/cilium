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

package driver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/pkg/client"

	"github.com/docker/libnetwork/ipams/remote/api"
)

const (
	PoolIPv4 = "CiliumPoolv4"
	PoolIPv6 = "CiliumPoolv6"
)

func (driver *driver) ipamCapabilities(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(&api.GetCapabilityResponse{})
	if err != nil {
		log.Fatalf("capabilities encode: %s", err)
		sendError(w, "encode error", http.StatusInternalServerError)
		return
	}
	log.Debug("IPAM capabilities exchange complete")
}

func (driver *driver) getDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	log.Debugf("GetDefaultAddressSpaces Called")

	resp := &api.GetAddressSpacesResponse{
		LocalDefaultAddressSpace:  "CiliumLocal",
		GlobalDefaultAddressSpace: "CiliumGlobal",
	}

	log.Debugf("Get Default Address Spaces response: %+v", resp)
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

	log.Debugf("Request Pool request: %+v", &req)
	resp := driver.getPoolResponse(&req)
	log.Debugf("Request Pool response: %+v", resp)
	objectResponse(w, resp)
}

func (driver *driver) releasePool(w http.ResponseWriter, r *http.Request) {
	var release api.ReleasePoolRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Release Pool request: %+v", &release)

	emptyResponse(w)
}

func (driver *driver) requestAddress(w http.ResponseWriter, r *http.Request) {
	var request api.RequestAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Request Address request: %+v", &request)

	family := client.AddressFamilyIPv6 // Default
	switch request.PoolID {
	case PoolIPv4:
		family = client.AddressFamilyIPv4
	case PoolIPv6:
		family = client.AddressFamilyIPv6
	}

	ipam, err := driver.client.IPAMAllocate(family)
	if err != nil {
		sendError(w, fmt.Sprintf("Could not allocate IP address: %s", err), http.StatusBadRequest)
		return
	}

	addr := ipam.Endpoint
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

	log.Debugf("Request Address response: %+v", resp)
	objectResponse(w, resp)
}

func (driver *driver) releaseAddress(w http.ResponseWriter, r *http.Request) {
	var release api.ReleaseAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&release); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Release Address request: %+v", release)
	if err := driver.client.IPAMReleaseIP(release.Address); err != nil {
		sendError(w, fmt.Sprintf("Could not release IP address: %s", err), http.StatusBadRequest)
		return
	}

	emptyResponse(w)
}
