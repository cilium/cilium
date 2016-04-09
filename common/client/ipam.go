package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

// AllocateIPs sends a PUT request with containerID to the daemon. Returns an IPAMConfig
// if the daemon returns a http.StatusCreated, which means the allocation was successfully
// created.
func (cli Client) AllocateIPs(containerID string) (*types.IPAMConfig, error) {
	query := url.Values{}

	serverResp, err := cli.put("/allocator/container/"+containerID, query, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusCreated {
		return nil, processErrorBody(serverResp.body, nil)
	}

	var newIPAMConfig types.IPAMConfig
	if err := json.NewDecoder(serverResp.body).Decode(&newIPAMConfig); err != nil {
		return nil, err
	}

	return &newIPAMConfig, nil
}

// ReleaseIPs sends a DELETE request with containerID to the daemon.
func (cli Client) ReleaseIPs(containerID string) error {
	query := url.Values{}

	serverResp, err := cli.delete("/allocator/container/"+containerID, query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusNotFound {
		return processErrorBody(serverResp.body, nil)
	}

	return nil
}
