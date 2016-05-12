package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

// AllocateIP sends a POST request to allocate a new IP for the given options to the
// daemon. Returns an IPAMConfig if the daemon returns a http.StatusCreated, which means
// the allocation was successfully made.
func (cli Client) AllocateIP(ipamType types.IPAMType, options types.IPAMReq) (*types.IPAMRep, error) {
	query := url.Values{}

	serverResp, err := cli.post("/allocator/ipam-allocate/"+string(ipamType), query, options, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusCreated &&
		serverResp.statusCode != http.StatusNoContent {
		return nil, processErrorBody(serverResp.body, nil)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	var newIPAMConfig types.IPAMRep
	if err := json.NewDecoder(serverResp.body).Decode(&newIPAMConfig); err != nil {
		return nil, err
	}

	return &newIPAMConfig, nil
}

// ReleaseIP sends a POST request to release the IP of the given options.
func (cli Client) ReleaseIP(ipamType types.IPAMType, options types.IPAMReq) error {
	query := url.Values{}

	serverResp, err := cli.post("/allocator/ipam-release/"+string(ipamType), query, options, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent {
		return processErrorBody(serverResp.body, nil)
	}

	return nil
}

// GetIPAMConf sends a POST request to retrieve the IPAM configuration for the given
// ipamType.
func (cli Client) GetIPAMConf(ipamType types.IPAMType, options types.IPAMReq) (*types.IPAMConfigRep, error) {
	query := url.Values{}

	serverResp, err := cli.post("/allocator/ipam-configuration/"+string(ipamType), query, options, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK {
		return nil, processErrorBody(serverResp.body, nil)
	}

	var newIPAMRep types.IPAMConfigRep
	if err := json.NewDecoder(serverResp.body).Decode(&newIPAMRep); err != nil {
		return nil, err
	}

	return &newIPAMRep, nil
}
