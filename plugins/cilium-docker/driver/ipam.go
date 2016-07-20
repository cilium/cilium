package driver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noironetworks/cilium-net/common/ipam"

	"github.com/docker/libnetwork/ipams/remote/api"
)

func (driver *driver) ipamCapabilities(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(&api.GetCapabilityResponse{
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
	} else {
		sendError(w, "No address provided by IPAM backend", http.StatusBadRequest)
		return
	}

	var resp *api.RequestAddressResponse
	if ipConfig != nil {
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
