package cilium_net_client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

func (cli Client) PolicyAdd(path string, node types.PolicyNode) error {
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

	jd := json.NewDecoder(serverResp.body)
	var pn types.PolicyNode
	if err := jd.Decode(&pn); err != nil {
		return nil, err
	}

	return &pn, nil
}
