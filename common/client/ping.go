package client

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Ping sends a GET request to the daemon. Returns "Pong" if the communication between the
// client and the server was successful.
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
