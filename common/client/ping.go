//
// Copyright 2016 Authors of Cilium
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
//
package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/common/types"
)

// Ping sends a GET request to the daemon. Returns "Pong" if the communication between the
// client and the server was successful.
func (cli Client) Ping() (*types.PingResponse, error) {
	serverResp, err := cli.R().Get("/ping")
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK {
		return nil, processErrorBody(serverResp.Body(), nil)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var resp types.PingResponse
	if err := json.Unmarshal(serverResp.Body(), &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
