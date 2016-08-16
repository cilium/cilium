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

// PolicyAdd sends a POST request with node to the "/policy/+path" endpoint to the daemon.
func (cli Client) PolicyAdd(path string, node *types.PolicyNode) error {

	serverResp, err := cli.R().SetBody(node).Post("/policy/" + path)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusCreated {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// PolicyDelete sends a DELETE request to the "/policy/+path" endpoint to the daemon.
func (cli Client) PolicyDelete(path string) error {

	serverResp, err := cli.R().Delete("/policy/" + path)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent &&
		serverResp.StatusCode() != http.StatusNotFound {
		return processErrorBody(serverResp.Body(), path)
	}

	return nil
}

// PolicyGet sends a GET request to the "/policy/+path" endpoint to the daemon. If the
// daemon returns a http.StatusOK means the policy was found and is returned. If the
// daemon returns a http.StatusNoContent the policy was not found and *types.PolicyNode is
// nil.
func (cli Client) PolicyGet(path string) (*types.PolicyNode, error) {

	serverResp, err := cli.R().Get("/policy/" + path)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent &&
		serverResp.StatusCode() != http.StatusOK {
		return nil, processErrorBody(serverResp.Body(), nil)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var pn types.PolicyNode
	if err := json.Unmarshal(serverResp.Body(), &pn); err != nil {
		return nil, err
	}

	return &pn, nil
}

func (cli Client) PolicyCanConsume(ctx *types.SearchContext) (*types.SearchContextReply, error) {

	serverResp, err := cli.R().SetBody(ctx).Post("/policy-consume-decision")
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusAccepted {
		return nil, processErrorBody(serverResp.Body(), nil)
	}

	var scr types.SearchContextReply
	if err := json.Unmarshal(serverResp.Body(), &scr); err != nil {
		return nil, err
	}
	return &scr, nil
}
