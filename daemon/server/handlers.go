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
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"

	"github.com/gorilla/mux"
)

func verifyEndpointID(vars map[string]string) (uint16, error) {
	if val, exists := vars["endpointID"]; !exists {
		return 0, errors.New("server received empty endpoint id")
	} else {
		i, err := strconv.ParseUint(val, 10, 16)
		return uint16(i), err
	}
}

func (router *Router) ping(w http.ResponseWriter, r *http.Request) {
	if resp, err := router.daemon.Ping(); err != nil {
		processServerError(w, r, err)
	} else {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			processServerError(w, r, err)
		}
	}
}

func (router *Router) globalStatus(w http.ResponseWriter, r *http.Request) {
	if resp, err := router.daemon.GlobalStatus(); err != nil {
		processServerError(w, r, err)
	} else {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			processServerError(w, r, err)
		}
	}
}

func (router *Router) update(w http.ResponseWriter, r *http.Request) {
	var opts types.OptionMap
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.Update(opts); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (router *Router) endpointCreate(w http.ResponseWriter, r *http.Request) {
	d := json.NewDecoder(r.Body)
	var ep types.Endpoint
	if err := d.Decode(&ep); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.EndpointJoin(ep); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (router *Router) endpointDelete(w http.ResponseWriter, r *http.Request) {
	val, err := verifyEndpointID(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.EndpointLeave(val); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) endpointLeaveByDockerEPID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dockerEPID, exists := vars["dockerEPID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty docker endpoint id"))
		return
	}
	if err := router.daemon.EndpointLeaveByDockerEPID(dockerEPID); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) endpointUpdate(w http.ResponseWriter, r *http.Request) {
	val, err := verifyEndpointID(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	var opts types.OptionMap
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.EndpointUpdate(val, opts); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (router *Router) endpointSave(w http.ResponseWriter, r *http.Request) {
	var ep types.Endpoint
	if err := json.NewDecoder(r.Body).Decode(&ep); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.EndpointSave(ep); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (router *Router) endpointLabelsGet(w http.ResponseWriter, r *http.Request) {
	epID, err := verifyEndpointID(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if lbls, err := router.daemon.EndpointLabelsGet(epID); err != nil {
		processServerError(w, r, err)
	} else {
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(lbls); err != nil {
			processServerError(w, r, err)
		}
	}
}

func (router *Router) endpointLabelsUpdate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	epID, err := verifyEndpointID(vars)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	var labelOp types.LabelOp
	if err := json.NewDecoder(r.Body).Decode(&labelOp); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.EndpointLabelsUpdate(epID, labelOp); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (router *Router) endpointGet(w http.ResponseWriter, r *http.Request) {
	epID, err := verifyEndpointID(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	ep, err := router.daemon.EndpointGet(epID)
	if err != nil {
		processServerError(w, r, fmt.Errorf("error while getting endpoint: %s", err))
		return
	}
	if ep == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(ep); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) endpointGetByDockerEPID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dockerEPID, exists := vars["dockerEPID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty docker endpoint id"))
		return
	}
	ep, err := router.daemon.EndpointGetByDockerEPID(dockerEPID)
	if err != nil {
		processServerError(w, r, fmt.Errorf("error while getting endpoint: %s", err))
		return
	}
	if ep == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(ep); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) endpointGetByDockerID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dockerID, exists := vars["dockerID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty docker ID"))
		return
	}
	ep, err := router.daemon.EndpointGetByDockerID(dockerID)
	if err != nil {
		processServerError(w, r, fmt.Errorf("error while getting endpoint: %s", err))
		return
	}
	if ep == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(ep); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) endpointsGet(w http.ResponseWriter, r *http.Request) {
	eps, err := router.daemon.EndpointsGet()
	if err != nil {
		processServerError(w, r, fmt.Errorf("error while getting endpoints: %s", err))
		return
	}
	if eps == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(eps); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) ipamConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ipamType, exists := vars["ipam-type"]
	if !exists {
		processServerError(w, r, errors.New("server received empty ipam-type"))
		return
	}
	var opts ipam.IPAMReq
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		processServerError(w, r, err)
		return
	}
	ipamConfig, err := router.daemon.GetIPAMConf(ipam.IPAMType(ipamType), opts)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(ipamConfig); err != nil {
		processServerError(w, r, err)
		return
	}
}
func (router *Router) allocateIPv6(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ipamType, exists := vars["ipam-type"]
	if !exists {
		processServerError(w, r, errors.New("server received empty ipam-type"))
		return
	}
	var opts ipam.IPAMReq
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		processServerError(w, r, err)
		return
	}
	ipamConfig, err := router.daemon.AllocateIP(ipam.IPAMType(ipamType), opts)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if ipamConfig == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(ipamConfig); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) releaseIPv6(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ipamType, exists := vars["ipam-type"]
	if !exists {
		processServerError(w, r, errors.New("server received empty ipam-type"))
		return
	}
	var opts ipam.IPAMReq
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.ReleaseIP(ipam.IPAMType(ipamType), opts); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) getLabels(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["uuid"]
	if !exists {
		processServerError(w, r, errors.New("server received empty labels UUID"))
		return
	}
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		processServerError(w, r, fmt.Errorf("server received invalid UUID '%s': '%s'", idStr, err))
		return
	}
	labels, err := router.daemon.GetLabels(uint32(id))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if labels == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	e := json.NewEncoder(w)
	if err := e.Encode(labels); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) getLabelsBySHA256(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sha256sum, exists := vars["sha256sum"]
	if !exists {
		processServerError(w, r, errors.New("server received empty SHA256SUM"))
		return
	}
	labels, err := router.daemon.GetLabelsBySHA256(sha256sum)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if labels == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(labels); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) putLabels(w http.ResponseWriter, r *http.Request) {
	d := json.NewDecoder(r.Body)
	var labels types.Labels
	if err := d.Decode(&labels); err != nil {
		processServerError(w, r, err)
		return
	}
	vars := mux.Vars(r)
	contID, exists := vars["contID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty container ID"))
		return
	}
	secCtxLabels, _, err := router.daemon.PutLabels(labels, contID)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(secCtxLabels); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) deleteLabelsByUUID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["uuid"]
	if !exists {
		processServerError(w, r, errors.New("server received empty labels UUID"))
		return
	}
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		processServerError(w, r, fmt.Errorf("server received invalid UUID '%s': '%s'", idStr, err))
		return
	}
	contID, exists := vars["contID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty container ID"))
		return
	}
	if err := router.daemon.DeleteLabelsByUUID(uint32(id), contID); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) deleteLabelsBySHA256(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sha256sum, exists := vars["sha256sum"]
	if !exists {
		processServerError(w, r, errors.New("server received empty sha256sum"))
		return
	}
	contID, exists := vars["contID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty container ID"))
		return
	}
	if err := router.daemon.DeleteLabelsBySHA256(sha256sum, contID); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) getMaxUUID(w http.ResponseWriter, r *http.Request) {
	id, err := router.daemon.GetMaxLabelID()
	if err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(id); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) policyAdd(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path, exists := vars["path"]
	if !exists {
		processServerError(w, r, errors.New("server received empty policy path"))
		return
	}

	d := json.NewDecoder(r.Body)
	var pn types.PolicyNode
	if err := d.Decode(&pn); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.PolicyAdd(path, &pn); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (router *Router) policyAddForm(w http.ResponseWriter, r *http.Request) {
	const _4MBMemory = 4 << 20
	err := r.ParseMultipartForm(_4MBMemory)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	file, _, err := r.FormFile("policy-input-file")
	if err != nil {
		processServerError(w, r, err)
		return
	}
	var pn types.PolicyNode
	if err := json.NewDecoder(file).Decode(&pn); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.PolicyAdd(pn.Path(), &pn); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (router *Router) policyDelete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path, exists := vars["path"]
	if !exists {
		processServerError(w, r, errors.New("server received empty policy path"))
		return
	}

	if err := router.daemon.PolicyDelete(path); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) policyGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path, exists := vars["path"]
	if !exists {
		processServerError(w, r, errors.New("server received empty policy path"))
		return
	}

	tree, err := router.daemon.PolicyGet(path)
	if err != nil {
		processServerError(w, r, err)
		return
	}

	if tree == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	e := json.NewEncoder(w)
	if err := e.Encode(tree); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) policyCanConsume(w http.ResponseWriter, r *http.Request) {
	var sc types.SearchContext
	if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
		processServerError(w, r, err)
		return
	}
	scr, err := router.daemon.PolicyCanConsume(&sc)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(scr); err != nil {
		processServerError(w, r, err)
		return
	}
}

func verifyFESHA256Sum(vars map[string]string) (string, error) {
	if val, exists := vars["feSHA256Sum"]; !exists {
		return "", errors.New("server received empty feSHA256Sum")
	} else {
		return val, nil
	}
}

func (router *Router) serviceAdd(w http.ResponseWriter, r *http.Request) {
	addRevNAT := r.URL.Query().Get("rev-nat") == "true"
	var sv types.LBSVC
	if err := json.NewDecoder(r.Body).Decode(&sv); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.SVCAdd(sv.FE, sv.BES, addRevNAT); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (router *Router) serviceDel(w http.ResponseWriter, r *http.Request) {
	feSHA256Sum, err := verifyFESHA256Sum(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.SVCDeleteBySHA256Sum(feSHA256Sum); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) serviceDelAll(w http.ResponseWriter, r *http.Request) {
	if err := router.daemon.SVCDeleteAll(); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) serviceGet(w http.ResponseWriter, r *http.Request) {
	feSHA256Sum, err := verifyFESHA256Sum(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	lbSVC, err := router.daemon.SVCGetBySHA256Sum(feSHA256Sum)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if lbSVC == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(lbSVC); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) serviceDump(w http.ResponseWriter, r *http.Request) {
	dump, err := router.daemon.SVCDump()
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if dump == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(dump); err != nil {
		processServerError(w, r, err)
		return
	}
}

func verifyRevNATID(vars map[string]string) (types.ServiceID, error) {
	if val, exists := vars["revNATID"]; !exists {
		return 0, errors.New("server received rev NAT ID")
	} else {
		i, err := strconv.ParseUint(val, 10, 16)
		return types.ServiceID(i), err
	}
}

func (router *Router) revNATAdd(w http.ResponseWriter, r *http.Request) {
	var revNAT types.L3n4AddrID
	if err := json.NewDecoder(r.Body).Decode(&revNAT); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.RevNATAdd(revNAT.ID, revNAT.L3n4Addr); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (router *Router) revNATDel(w http.ResponseWriter, r *http.Request) {
	revNATID, err := verifyRevNATID(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.RevNATDelete(revNATID); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) revNATDelAll(w http.ResponseWriter, r *http.Request) {
	if err := router.daemon.RevNATDeleteAll(); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) revNATGet(w http.ResponseWriter, r *http.Request) {
	revNATID, err := verifyRevNATID(mux.Vars(r))
	if err != nil {
		processServerError(w, r, err)
		return
	}
	revNAT, err := router.daemon.RevNATGet(revNATID)
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if revNAT == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(revNAT); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) revNATDump(w http.ResponseWriter, r *http.Request) {
	dump, err := router.daemon.RevNATDump()
	if err != nil {
		processServerError(w, r, err)
		return
	}
	if dump == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(dump); err != nil {
		processServerError(w, r, err)
		return
	}
}

func (router *Router) syncLBMap(w http.ResponseWriter, r *http.Request) {
	err := router.daemon.SyncLBMap()
	if err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}
