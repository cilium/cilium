// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package probe

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// DefaultTimeout used for requests
var DefaultTimeout = 30 * time.Second

// Client for accessing the http probe
type Client struct {
	client *http.Client
	host   *url.URL
}

// NewClient creates a new http client with DefaultTransport
func NewClient(host string) (*Client, error) {
	hostURL, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	cl := &http.Client{Timeout: DefaultTimeout}
	return &Client{cl, hostURL}, nil
}

// GetHello performs a GET request on the /hello endpoint
func (c *Client) GetHello() error {
	requestURL, err := c.host.Parse("/hello")
	if err != nil {
		return err
	}

	resp, err := c.client.Get(requestURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}
