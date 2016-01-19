package cilium_net_client

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

func (cli *Client) EndpointCreate(ep types.Endpoint) error {
	query := url.Values{}

	serverResp, err := cli.post("/endpoint/"+ep.ID, query, ep, nil)
	if err != nil {
		fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusCreated {
		return processErrorBody(serverResp.body, &ep)
	}

	return nil
}
