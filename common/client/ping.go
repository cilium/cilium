package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

// Ping sends a GET request to the daemon. Returns "Pong" if the communication between the
// client and the server was successful.
func (cli Client) Ping() (*types.PingResponse, error) {
	query := url.Values{}

	serverResp, err := cli.get("/ping", query, nil)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK {
		return nil, processErrorBody(serverResp.body, nil)
	}

	if serverResp.statusCode == http.StatusNoContent {
		return nil, nil
	}

	var resp types.PingResponse
	if err := json.NewDecoder(serverResp.body).Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
