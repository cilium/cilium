package cilium_net_client

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

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

func (cli Client) EndpointLeave(ep types.Endpoint) error {
	query := url.Values{}

	serverResp, err := cli.delete("/endpoint/"+ep.ID, query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusNoContent &&
		serverResp.statusCode != http.StatusNotFound {
		return processErrorBody(serverResp.body, ep)
	}

	return nil
}
