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
	"strconv"

	"github.com/cilium/cilium/common/types"
)

// EndpointJoin sends a endpoint POST request with ep to the daemon.
func (cli Client) EndpointJoin(ep types.Endpoint) error {

	serverResp, err := cli.R().SetBody(ep).Post("/endpoint/" + strconv.Itoa(int(ep.ID)))
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusCreated {
		return processErrorBody(serverResp.Body(), ep)
	}

	return nil
}

// EndpointLeave sends a DELETE request with epID to the daemon.
func (cli Client) EndpointLeave(epID uint16) error {

	log.Debugf("DELETE /endpoint/%d", epID)

	serverResp, err := cli.R().Delete("/endpoint/" + strconv.Itoa(int(epID)))
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent &&
		serverResp.StatusCode() != http.StatusNotFound {
		return processErrorBody(serverResp.Body(), epID)
	}

	return nil
}

// EndpointLeaveByDockerEPID sends a DELETE request with dockerEPID to the daemon.
func (cli Client) EndpointLeaveByDockerEPID(dockerEPID string) error {

	log.Debug("DELETE /endpoint-by-docker-ep-id/" + dockerEPID)

	serverResp, err := cli.R().Delete("/endpoint-by-docker-ep-id/" + dockerEPID)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent &&
		serverResp.StatusCode() != http.StatusNotFound {
		return processErrorBody(serverResp.Body(), dockerEPID)
	}

	return nil
}

// EndpointGet sends a GET request with epID to the daemon.
func (cli Client) EndpointGet(epID uint16) (*types.Endpoint, error) {

	serverResp, err := cli.R().Get("/endpoint/" + strconv.Itoa(int(epID)))
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK &&
		serverResp.StatusCode() != http.StatusNoContent {
		return nil, processErrorBody(serverResp.Body(), epID)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var ep types.Endpoint
	if err := json.Unmarshal(serverResp.Body(), &ep); err != nil {
		return nil, err
	}

	return &ep, nil
}

// EndpointGetByDockerEPID sends a GET request with dockerEPID to the daemon.
func (cli Client) EndpointGetByDockerEPID(dockerEPID string) (*types.Endpoint, error) {

	serverResp, err := cli.R().Get("/endpoint-by-docker-ep-id/" + dockerEPID)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK &&
		serverResp.StatusCode() != http.StatusNoContent {
		return nil, processErrorBody(serverResp.Body(), dockerEPID)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var ep types.Endpoint
	if err := json.Unmarshal(serverResp.Body(), &ep); err != nil {
		return nil, err
	}

	return &ep, nil
}

// EndpointGetByDockerID sends a GET request with dockerID to the daemon.
func (cli Client) EndpointGetByDockerID(dockerID string) (*types.Endpoint, error) {

	serverResp, err := cli.R().Get("/endpoint-by-docker-id/" + dockerID)
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK &&
		serverResp.StatusCode() != http.StatusNoContent {
		return nil, processErrorBody(serverResp.Body(), dockerID)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var ep types.Endpoint
	if err := json.Unmarshal(serverResp.Body(), &ep); err != nil {
		return nil, err
	}

	return &ep, nil
}

// EndpointsGet sends a GET request to the daemon.
func (cli Client) EndpointsGet() ([]types.Endpoint, error) {

	serverResp, err := cli.R().Get("/endpoints")
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK &&
		serverResp.StatusCode() != http.StatusNoContent {
		return nil, processErrorBody(serverResp.Body(), nil)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var eps []types.Endpoint
	if err := json.Unmarshal(serverResp.Body(), &eps); err != nil {
		return nil, err
	}

	return eps, nil
}

// EndpointUpdate sends a POST request with epID and opts to the daemon.
func (cli Client) EndpointUpdate(epID uint16, opts types.OptionMap) error {

	serverResp, err := cli.R().SetBody(opts).Post("/endpoint/update/" + strconv.Itoa(int(epID)))
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK &&
		serverResp.StatusCode() != http.StatusAccepted {
		return processErrorBody(serverResp.Body(), epID)
	}

	return nil
}

// EndpointSave sends a endpoint POST request with ep to the daemon.
func (cli Client) EndpointSave(ep types.Endpoint) error {

	serverResp, err := cli.R().SetBody(ep).Post("/endpoint/save/" + strconv.Itoa(int(ep.ID)))
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusCreated {
		return processErrorBody(serverResp.Body(), ep)
	}

	return nil
}

func (cli Client) EndpointLabelsGet(epID uint16) (*types.OpLabels, error) {

	serverResp, err := cli.R().Get("/endpoint/labels/" + strconv.Itoa(int(epID)))
	if err != nil {
		return nil, fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK &&
		serverResp.StatusCode() != http.StatusNoContent {
		return nil, processErrorBody(serverResp.Body(), epID)
	}

	if serverResp.StatusCode() == http.StatusNoContent {
		return nil, nil
	}

	var opLbls types.OpLabels
	if err := json.Unmarshal(serverResp.Body(), &opLbls); err != nil {
		return nil, err
	}

	return &opLbls, nil
}

func (cli Client) EndpointLabelsUpdate(epID uint16, labelOp types.LabelOp) error {
	serverResp, err := cli.R().SetBody(labelOp).Post(fmt.Sprintf("/endpoint/labels/%d", epID))
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusAccepted {
		return processErrorBody(serverResp.Body(), epID)
	}

	return nil
}
