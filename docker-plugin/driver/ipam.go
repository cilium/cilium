package driver

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/noironetworks/cilium-net/common"

	log "github.com/noironetworks/cilium-net/docker-plugin/Godeps/_workspace/src/github.com/Sirupsen/logrus"
	"github.com/noironetworks/cilium-net/docker-plugin/Godeps/_workspace/src/github.com/docker/libnetwork/ipams/remote/api"
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
	var poolID, pool, gw string

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Could not decode JSON encode payload", http.StatusBadRequest)
		return
	}

	log.Debugf("Request Pool request: %+v", &req)

	if req.V6 == false {
		log.Warnf("Docker requested us to use legacy IPv4, boooooring...")
		poolID = DefaultPoolV4
		pool = DummyV4AllocPool
		gw = DummyV4Gateway
	} else {
		poolID = DefaultPoolV6
		pool = driver.allocPool.String()
		gw = driver.nodeAddress.String() + "/128"
	}

	resp := &api.RequestPoolResponse{
		PoolID: poolID,
		Pool:   pool,
		Data: map[string]string{
			"com.docker.network.gateway": gw,
		},
	}

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

	var resp *api.RequestAddressResponse

	if request.PoolID == DefaultPoolV4 {
		/* Ignore */
	} else {
		v4IP, err := driver.allocatorRange.AllocateNext()
		if err != nil {
			sendError(w, "Could not allocate IP address", http.StatusBadRequest)
			return
		}

		ip := common.BuildEndpointAddress(driver.nodeAddress, v4IP)
		resp = &api.RequestAddressResponse{
			Address: ip.String() + "/128",
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

	log.Debugf("Release Address request: %+v", &release)

	err := driver.allocatorRange.Release(net.ParseIP(release.Address))
	if err != nil {
		sendError(w, "Unable to release IP address", http.StatusBadRequest)
		return
	}

	emptyResponse(w)
}
