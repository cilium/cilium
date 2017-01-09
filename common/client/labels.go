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

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
)

// PutLabels sends POST request with labels to the daemon. Returns
func (cli Client) PutLabels(lbls labels.Labels, contID string) (*policy.Identity, bool, error) {

	serverResp, err := cli.R().SetBody(lbls).Post("/labels/" + contID)
	if err != nil {
		return nil, false, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusAccepted {
		return nil, false, processErrorBody(serverResp.Body(), nil)
	}

	// TODO: check if the value is new or not. Possible by checking if labelsResp.RefCount == 1
	var labelsResp policy.Identity
	if err := json.Unmarshal(serverResp.Body(), &labelsResp); err != nil {
		return nil, false, err
	}

	return &labelsResp, false, nil
}

// GetLabels sends a GET request with id to the daemon. Returns the policy.Identitys
// with the given id. If it's not found, policy.Identitys and error are booth nil.
func (cli Client) GetLabels(id policy.NumericIdentity) (*policy.Identity, error) {
	serverResp, err := cli.R().Get("/labels/by-uuid/" + id.StringID())
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

	var res policy.Identity
	if err := json.Unmarshal(serverResp.Body(), &res); err != nil {
		return nil, err
	}

	return &res, nil
}

// GetLabelsBySHA256 sends a GET request with sha256sum to the daemon. Returns the
// policy.Identitys with the given id. If it's not found, policy.Identitys and error
// are booth nil.
func (cli Client) GetLabelsBySHA256(sha256sum string) (*policy.Identity, error) {

	serverResp, err := cli.R().Get("/labels/by-sha256sum/" + sha256sum)
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

	var secCtxLabels policy.Identity
	if err := json.Unmarshal(serverResp.Body(), &secCtxLabels); err != nil {
		return nil, err
	}

	return &secCtxLabels, nil
}

// DeleteLabelsByUUID sends a DELETE request with id to the daemon.
func (cli Client) DeleteLabelsByUUID(id policy.NumericIdentity, contID string) error {
	serverResp, err := cli.R().Delete("/labels/by-uuid/" + id.StringID() + "/" + contID)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// DeleteLabelsBySHA256 sends a DELETE request with the sha256sum to the daemon.
func (cli Client) DeleteLabelsBySHA256(sha256sum, contID string) error {

	serverResp, err := cli.R().Delete("/labels/by-sha256sum/" + sha256sum + "/" + contID)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// GetMaxLabelID sends a GET request to the daemon. Returns the next, possible, free UUID.
func (cli Client) GetMaxLabelID() (policy.NumericIdentity, error) {

	serverResp, err := cli.R().Get("/labels/status/maxUUID")
	if err != nil {
		return 0, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK {
		return 0, processErrorBody(serverResp.Body(), nil)
	}

	var maxID policy.NumericIdentity
	if err := json.Unmarshal(serverResp.Body(), &maxID); err != nil {
		return 0, err
	}

	return maxID, nil
}
