package cilium_net_client

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/noironetworks/cilium-net/common/types"
)

func (cli Client) Ping() (string, error) {
	query := url.Values{}

	serverResp, err := cli.get("/ping", query, nil)
	if err != nil {
		return "", fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	bytes, err := ioutil.ReadAll(serverResp.body)
	if err != nil {
		return "", fmt.Errorf("%s", string(bytes))
	}

	if serverResp.statusCode != http.StatusOK {
		bytes, err := ioutil.ReadAll(serverResp.body)
		if err != nil {
			return "", fmt.Errorf("error retrieving server body response: %s", err)
		}
		return "", fmt.Errorf("%s", string(bytes))
	}

	return string(bytes), nil
}

func (cli Client) EndpointJoin(ep types.Endpoint) error {
	return nil
}
func (cli Client) EndpointLeave(ep types.Endpoint) error {
	return nil
}
