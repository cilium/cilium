package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

// PolicyAdd sends a POST request with node to the "/policy/+path" endpoint to the daemon.
func (cli Client) PolicyAdd(path string, node *types.PolicyNode) error {
	query := url.Values{}
	serverResp, err := cli.post("/policy/"+path, query, node, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusCreated {
		return processErrorBody(serverResp.body, nil)
	}

	return nil
}

// PolicyDelete sends a DELETE request to the "/policy/+path" endpoint to the daemon.
func (cli Client) PolicyDelete(path string) error {
	query := url.Values{}

	serverResp, err := cli.delete("/policy/"+path, query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusNotFound {
		return processErrorBody(serverResp.body, path)
	}

	return nil
}

// PolicyGet sends a GET request to the "/policy/+path" endpoint to the daemon. If the
// daemon returns a http.StatusOK means the policy was found and is returned. If the
// daemon returns a http.StatusNoContent the policy was not found and *types.PolicyNode is
// nil.
func (cli Client) PolicyGet(path string) (*types.PolicyNode, error) {
	query := url.Values{}

	serverResp, err := cli.get("/policy/"+path, query, nil)
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

	var pn types.PolicyNode
	if err := json.NewDecoder(serverResp.body).Decode(&pn); err != nil {
		return nil, err
	}

	return &pn, nil
}

func (cli Client) PolicyCanConsume(ctx *types.SearchContext) (*types.SearchContextReply, error) {
	query := url.Values{}

	serverResp, err := cli.post("/policy-consume-decision", query, ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusAccepted {
		return nil, processErrorBody(serverResp.body, nil)
	}

	var scr types.SearchContextReply
	if err := json.NewDecoder(serverResp.body).Decode(&scr); err != nil {
		return nil, err
	}
	return &scr, nil
}
