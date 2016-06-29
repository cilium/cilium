package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noironetworks/cilium-net/common/types"
)

// Ping sends a GET request to the daemon. Returns "Pong" if the communication between the
// client and the server was successful.
func (cli Client) Ping() (*types.PingResponse, error) {
	serverResp, err := cli.R().Get("/ping")
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK {
		return nil, processErrorBody(serverResp.Body(), nil)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var resp types.PingResponse
	if err := json.Unmarshal(serverResp.Body(), &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
