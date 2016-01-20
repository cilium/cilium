package cilium_net_client

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func (cli Client) Ping() (string, error) {
	query := url.Values{}

	serverResp, err := cli.get("/ping", query, nil)
	if err != nil {
		return "", fmt.Errorf("error while connecting to daemon: %s", err)
	}

	defer ensureReaderClosed(serverResp)

	if serverResp.statusCode != http.StatusOK {
		return "", processErrorBody(serverResp.body, nil)
	}

	bytes, err := ioutil.ReadAll(serverResp.body)
	if err != nil {
		return "", fmt.Errorf("%s", string(bytes))
	}

	return string(bytes), nil
}
