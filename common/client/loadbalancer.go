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

// SVCAdd sends a POST request with the given frontend and respective backends to the
// daemon. The addRevNAT will be sent as an URL query value.
func (cli Client) SVCAdd(fe types.L3n4AddrID, bes []types.L3n4Addr, addRevNAT bool) error {
	svcRest := types.LBSVC{
		FE:  fe,
		BES: bes,
	}
	serverResp, err := cli.R().SetQueryParam("rev-nat", strconv.FormatBool(addRevNAT)).
		SetBody(svcRest).Post("/lb/service")

	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusCreated {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// SVCDelete calculates the SHA256Sum from the given frontend and sends a DELETE request
// to the daemon.
func (cli Client) SVCDelete(fe types.L3n4Addr) error {
	feSHA256Sum, err := fe.SHA256Sum()
	if err != nil {
		return fmt.Errorf("invalid SHA256Sum for front end %+v: %s", fe, err)
	}
	return cli.SVCDeleteBySHA256Sum(feSHA256Sum)
}

// SVCDeleteBySHA256Sum sends a DELETE request with the given feSHA256Sum to delete the
// frontend, and respective backends, on the daemon.
func (cli Client) SVCDeleteBySHA256Sum(feSHA256Sum string) error {
	serverResp, err := cli.R().Delete("/lb/service/" + feSHA256Sum)
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// SVCDeleteAll sends a DELETE request to the daemon to delete all services in the daemon.
func (cli Client) SVCDeleteAll() error {
	serverResp, err := cli.R().Delete("/lb/services")
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// SVCGet calculates the SHA256Sum from the given frontend and sends a GET request with
// the calculated SHA256Sum to the daemon.
func (cli Client) SVCGet(fe types.L3n4Addr) (*types.LBSVC, error) {
	feSHA256Sum, err := fe.SHA256Sum()
	if err != nil {
		return nil, fmt.Errorf("invalid SHA256Sum for front end %+v: %s", fe, err)
	}
	return cli.SVCGetBySHA256Sum(feSHA256Sum)
}

// SVCGetBySHA256Sum sends a GET request with the given feSHA256Sum to the daemon.
func (cli Client) SVCGetBySHA256Sum(feSHA256Sum string) (*types.LBSVC, error) {
	serverResp, err := cli.R().Get("/lb/service/" + feSHA256Sum)
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

	var lbSvc types.LBSVC
	if err := json.Unmarshal(serverResp.Body(), &lbSvc); err != nil {
		return nil, err
	}

	return &lbSvc, nil
}

// SVCDump sends a GET request to receive all services (frontend with respective backends)
// stored in the daemon.
func (cli Client) SVCDump() ([]types.LBSVC, error) {
	serverResp, err := cli.R().Get("/lb/services")
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

	dump := []types.LBSVC{}
	if err := json.Unmarshal(serverResp.Body(), &dump); err != nil {
		return nil, err
	}

	return dump, nil
}

// RevNATAdd sends a POST request with the RevNAT to the daemon.
func (cli Client) RevNATAdd(id types.ServiceID, revNATValue types.L3n4Addr) error {
	revNAT := types.L3n4AddrID{
		ID:       id,
		L3n4Addr: revNATValue,
	}
	serverResp, err := cli.R().SetBody(revNAT).Post("/lb/revnat")

	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusCreated {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// RevNATDelete sends a DELETE request with the id to the daemon.
func (cli Client) RevNATDelete(id types.ServiceID) error {
	serverResp, err := cli.R().Delete("/lb/revnat/" + strconv.FormatUint(uint64(id), 10))
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// RevNATDeleteAll sends a DELETE request to delete all RevNAT on the daemon.
func (cli Client) RevNATDeleteAll() error {
	serverResp, err := cli.R().Delete("/lb/revnats")
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusNoContent {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}

// RevNATGet sends a GET request with the revNATID to receive the revNAT that belongs to
// the given revNATID.
func (cli Client) RevNATGet(revNATID types.ServiceID) (*types.L3n4Addr, error) {
	serverResp, err := cli.R().Get("/lb/revnat/" + strconv.FormatUint(uint64(revNATID), 10))
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

	var revNAT types.L3n4Addr
	if err := json.Unmarshal(serverResp.Body(), &revNAT); err != nil {
		return nil, err
	}

	return &revNAT, nil
}

// RevNATDump sends a GET request to receive all revnats stored, from the daemon.
func (cli Client) RevNATDump() ([]types.L3n4AddrID, error) {
	serverResp, err := cli.R().Get("/lb/revnats")
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

	var dump []types.L3n4AddrID
	if err := json.Unmarshal(serverResp.Body(), &dump); err != nil {
		return nil, err
	}

	return dump, nil
}

// SyncLBMap sends a POST request to the daemon to sync all LB maps.
func (cli Client) SyncLBMap() error {
	serverResp, err := cli.R().Post("/lb/synclbmap")
	if err != nil {
		return fmt.Errorf("error while connecting to daemon: %s", err)
	}

	if serverResp.StatusCode() != http.StatusOK {
		return processErrorBody(serverResp.Body(), nil)
	}

	return nil
}
