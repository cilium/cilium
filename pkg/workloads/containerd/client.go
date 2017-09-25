// Copyright 2017 Authors of Cilium
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

package containerd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/docker/engine-api/client"
	dTypes "github.com/docker/engine-api/types"
	dNetwork "github.com/docker/engine-api/types/network"
)

var (
	dockerClient *client.Client
)

// Client returns the default containerd client
func Client() *client.Client {
	return dockerClient
}

// Init initializes the containerd package
func Init(endpoint string) error {
	defaultHeaders := map[string]string{"User-Agent": "cilium"}
	c, err := client.NewClient(endpoint, "v1.21", nil, defaultHeaders)
	if err != nil {
		return err
	}

	dockerClient = c

	return nil
}

// InitMock initializes the containerd packged with a mocked runtime
func InitMock() error {
	mwc := newMockClient(networksMock())
	c, err := client.NewClient("http://127.0.0.1:2375", "v1.21", mwc, nil)
	if err != nil {
		return err
	}

	dockerClient = c

	return nil
}

// Helper function to mock docker calls
type transportFunc func(*http.Request) (*http.Response, error)

// Helper function to mock docker calls
func (tf transportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return tf(req)
}

// Helper function to mock docker calls
func newMockClient(doer func(*http.Request) (*http.Response, error)) *http.Client {
	v := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	v.RegisterProtocol("http", transportFunc(doer))
	return &http.Client{
		Transport: http.RoundTripper(v),
	}
}

// Helper function to mock docker calls to networks endpoint
func networksMock() func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.URL.Path, "/v1.21/networks") {
			return nil, fmt.Errorf("Only expecting /v1.21/networks requests, got %s", req.URL.Path)
		}

		header := http.Header{}
		header.Set("Content-Type", "application/json")

		body, err := json.Marshal(&dTypes.NetworkResource{
			Name:       "12345",
			ID:         "1234",
			Scope:      "global",
			Driver:     "cilium-net",
			EnableIPv6: true,
			IPAM:       dNetwork.IPAM{},
			Internal:   false,
			// this map contains all endpoints except 259
			Containers: map[string]dTypes.EndpointResource{
				"603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def00100256": {
					EndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d800200256",
				},
				"603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def00100257": {
					EndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d800200257",
				},
				"603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def00100258": {
					EndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d800100258",
				},
			},
			Options: map[string]string{},
			Labels:  map[string]string{},
		})
		if err != nil {
			return nil, err
		}

		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewReader(body)),
			Header:     header,
		}, nil
	}
}
