//
// Copyright 2016 Authors of Cilium
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
//
package driver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/common/ipam"

	"github.com/docker/libnetwork/ipams/remote/api"
)

type compatGetCapabilityResponse struct {
	SupportsAutoIPv6 bool
}

func (driver *driver) ipamCapabilities(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(&compatGetCapabilityResponse{
		SupportsAutoIPv6: true,
	})
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

func (driver *driver) requestPool(w http.ResponseWriter, r *http.Request) {
	var req api.RequestPoolRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Request Pool request: %+v", &req)

	pr, err := driver.client.GetIPAMConf(ipam.LibnetworkIPAMType, ipam.IPAMReq{RequestPoolRequest: &req})

	if err != nil {
		sendError(w, fmt.Sprintf("Could not get cilium IPAM configuration: %s", err), http.StatusBadRequest)
	}

	resp := pr.RequestPoolResponse

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

	ipConfig, err := driver.client.AllocateIP(ipam.LibnetworkIPAMType,
		ipam.IPAMReq{RequestAddressRequest: &request},
	)

	if err != nil {
		sendError(w, fmt.Sprintf("Could not allocate IP address: %s", err), http.StatusBadRequest)
		return
	}

	var addr string
	if ipConfig.IP6 != nil {
		addr = ipConfig.IP6.IP.IP.String() + "/128"
	} else if ipConfig.IP4 != nil {
		addr = ipConfig.IP4.IP.IP.String() + "/32"
	}

	var resp *api.RequestAddressResponse
	if ipConfig.IP6 != nil || ipConfig.IP4 != nil {
		resp = &api.RequestAddressResponse{
			Address: addr,
		}
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

	err := driver.client.ReleaseIP(ipam.LibnetworkIPAMType,
		ipam.IPAMReq{ReleaseAddressRequest: &release})
	if err != nil {
		sendError(w, fmt.Sprintf("Could not release IP address: %s", err), http.StatusBadRequest)
		return
	}

	emptyResponse(w)
}
