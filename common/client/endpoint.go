package client

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

// EndpointJoin sends a endpoint POST request with ep to the daemon.
func (cli Client) EndpointJoin(ep types.Endpoint) error {
	query := url.Values{}

	serverResp, err := cli.post("/endpoint/"+ep.ID, query, ep, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusCreated {
		return processErrorBody(serverResp.body, ep)
	}

	return nil
}

// EndpointLeave sends a DELETE request with epID to the daemon.
func (cli Client) EndpointLeave(epID string) error {
	query := url.Values{}

	log.Debug("DELETE /endpoint/" + epID)

	serverResp, err := cli.delete("/endpoint/"+epID, query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusNotFound {
		return processErrorBody(serverResp.body, epID)
	}

	return nil
}
