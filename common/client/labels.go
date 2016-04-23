package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/noironetworks/cilium-net/common/types"
)

// PutLabels sends POST request with labels to the daemon. Returns
func (cli Client) PutLabels(labels types.Labels) (*types.SecCtxLabel, bool, error) {
	query := url.Values{}
	serverResp, err := cli.post("/labels", query, labels, nil)
	if err != nil {
		return nil, false, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusAccepted {
		return nil, false, processErrorBody(serverResp.body, nil)
	}

	// TODO: check if the value is new or not. Possible by checking if labelsResp.RefCount == 1
	var labelsResp types.SecCtxLabel
	if err := json.NewDecoder(serverResp.body).Decode(&labelsResp); err != nil {
		return nil, false, err
	}

	return &labelsResp, false, nil
}

// GetLabels sends a GET request with id to the daemon. Returns the types.SecCtxLabels
// with the given id. If it's not found, types.SecCtxLabels and error are booth nil.
func (cli Client) GetLabels(id int) (*types.SecCtxLabel, error) {
	query := url.Values{}

	serverResp, err := cli.get("/labels/by-uuid/"+strconv.Itoa(id), query, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusOK {
		return nil, processErrorBody(serverResp.body, nil)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	var secCtxLabels types.SecCtxLabel
	if err := json.NewDecoder(serverResp.body).Decode(&secCtxLabels); err != nil {
		return nil, err
	}

	return &secCtxLabels, nil
}

// GetLabelsBySHA256 sends a GET request with sha256sum to the daemon. Returns the
// types.SecCtxLabels with the given id. If it's not found, types.SecCtxLabels and error
// are booth nil.
func (cli Client) GetLabelsBySHA256(sha256sum string) (*types.SecCtxLabel, error) {
	query := url.Values{}

	serverResp, err := cli.get("/labels/by-sha256sum/"+sha256sum, query, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusOK {
		return nil, processErrorBody(serverResp.body, nil)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	var secCtxLabels types.SecCtxLabel
	if err := json.NewDecoder(serverResp.body).Decode(&secCtxLabels); err != nil {
		return nil, err
	}

	return &secCtxLabels, nil
}

// DeleteLabelsByUUID sends a DELETE request with id to the daemon.
func (cli Client) DeleteLabelsByUUID(id int) error {
	query := url.Values{}

	serverResp, err := cli.delete("/labels/by-uuid/"+strconv.Itoa(id), query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent {
		return processErrorBody(serverResp.body, nil)
	}

	return nil
}

// DeleteLabelsBySHA256 sends a DELETE request with the sha256sum to the daemon.
func (cli Client) DeleteLabelsBySHA256(sha256sum string) error {
	query := url.Values{}

	serverResp, err := cli.delete("/labels/by-sha256sum/"+sha256sum, query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent {
		return processErrorBody(serverResp.body, nil)
	}

	return nil
}

// GetMaxID sends a GET request to the daemon. Returns the next, possible, free UUID.
func (cli Client) GetMaxID() (int, error) {
	query := url.Values{}

	serverResp, err := cli.get("/labels/status/maxUUID", query, nil)
	if err != nil {
		return -1, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK {
		return -1, processErrorBody(serverResp.body, nil)
	}

	var maxID int
	if err := json.NewDecoder(serverResp.body).Decode(&maxID); err != nil {
		return -1, err
	}

	return maxID, nil
}
