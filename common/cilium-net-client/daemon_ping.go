package cilium_net_client

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func (cli *Client) Ping() error {
	query := url.Values{}

	serverResp, err := cli.get("/ping", query, nil)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	bytes, err := ioutil.ReadAll(serverResp.body)
	if err != nil {
		return fmt.Errorf("%s", string(bytes))
	}

	if serverResp.statusCode != http.StatusOK {
		bytes, err := ioutil.ReadAll(serverResp.body)
		if err != nil {
			fmt.Errorf("error retrieving server body response: %s", err)
		}
		fmt.Errorf("%s", string(bytes))
	}

	return nil
}
