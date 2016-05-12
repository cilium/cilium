package client

import (
	"encoding/json"
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

// EndpointLeaveByDockerEPID sends a DELETE request with dockerEPID to the daemon.
func (cli Client) EndpointLeaveByDockerEPID(dockerEPID string) error {
	query := url.Values{}

	log.Debug("DELETE /endpoint-by-docker-ep-id/" + dockerEPID)

	serverResp, err := cli.delete("/endpoint-by-docker-ep-id/"+dockerEPID, query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusNotFound {
		return processErrorBody(serverResp.body, dockerEPID)
	}

	return nil
}

// EndpointGet sends a GET request with epID to the daemon.
func (cli Client) EndpointGet(epID string) (*types.Endpoint, error) {
	query := url.Values{}
	serverResp, err := cli.get("/endpoint/"+epID, query, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK &&
		serverResp.statusCode != http.StatusNoContent {
		return nil, processErrorBody(serverResp.body, epID)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	var ep types.Endpoint
	if err := json.NewDecoder(serverResp.body).Decode(&ep); err != nil {
		return nil, err
	}

	return &ep, nil
}

// EndpointGetByDockerEPID sends a GET request with dockerEPID to the daemon.
func (cli Client) EndpointGetByDockerEPID(dockerEPID string) (*types.Endpoint, error) {
	query := url.Values{}
	serverResp, err := cli.get("/endpoint-by-docker-ep-id/"+dockerEPID, query, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK &&
		serverResp.statusCode != http.StatusNoContent {
		return nil, processErrorBody(serverResp.body, dockerEPID)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	var ep types.Endpoint
	if err := json.NewDecoder(serverResp.body).Decode(&ep); err != nil {
		return nil, err
	}

	return &ep, nil
}

// EndpointsGet sends a GET request to the daemon.
func (cli Client) EndpointsGet() ([]types.Endpoint, error) {
	query := url.Values{}
	serverResp, err := cli.get("/endpoints", query, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK &&
		serverResp.statusCode != http.StatusNoContent {
		return nil, processErrorBody(serverResp.body, nil)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	var eps []types.Endpoint
	if err := json.NewDecoder(serverResp.body).Decode(&eps); err != nil {
		return nil, err
	}

	return eps, nil
}

// EndpointUpdate sends a POST request with epID and opts to the daemon.
func (cli Client) EndpointUpdate(epID string, opts types.EPOpts) error {
	query := url.Values{}
	serverResp, err := cli.post("/endpoint/update/"+epID, query, opts, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK &&
		serverResp.statusCode != http.StatusAccepted {
		return processErrorBody(serverResp.body, epID)
	}

	return nil
}

// EndpointSave sends a endpoint POST request with ep to the daemon.
func (cli Client) EndpointSave(ep types.Endpoint) error {
	query := url.Values{}
	serverResp, err := cli.post("/endpoint/save/"+ep.ID, query, ep, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusCreated {
		return processErrorBody(serverResp.body, ep)
	}

	return nil
}
