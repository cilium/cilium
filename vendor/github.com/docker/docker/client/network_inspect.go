package client

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/docker/docker/api/types"
	"golang.org/x/net/context"
)

// NetworkInspect returns the information for a specific network configured in the docker host.
func (cli *Client) NetworkInspect(ctx context.Context, networkID string, options types.NetworkInspectOptions) (types.NetworkResource, error) {
	networkResource, _, err := cli.NetworkInspectWithRaw(ctx, networkID, options)
	return networkResource, err
}

// NetworkInspectWithRaw returns the information for a specific network configured in the docker host and its raw representation.
func (cli *Client) NetworkInspectWithRaw(ctx context.Context, networkID string, options types.NetworkInspectOptions) (types.NetworkResource, []byte, error) {
	var (
		networkResource types.NetworkResource
		resp            serverResponse
		err             error
	)
	query := url.Values{}
	if options.Verbose {
		query.Set("verbose", "true")
	}
	if options.Scope != "" {
		query.Set("scope", options.Scope)
	}
	resp, err = cli.get(ctx, "/networks/"+networkID, query, nil)
	if err != nil {
		if resp.statusCode == http.StatusNotFound {
			return networkResource, nil, networkNotFoundError{networkID}
		}
		return networkResource, nil, err
	}
	defer ensureReaderClosed(resp)

	body, err := ioutil.ReadAll(resp.body)
	if err != nil {
		return networkResource, nil, err
	}
	rdr := bytes.NewReader(body)
	err = json.NewDecoder(rdr).Decode(&networkResource)
	return networkResource, body, err
}
