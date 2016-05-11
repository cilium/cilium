package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/noironetworks/cilium-net/common/types"

	"github.com/gorilla/mux"
)

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
	vars := mux.Vars(r)
	val, exists := vars["endpointID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty endpoint id"))
		return
	}
	if err := router.daemon.EndpointLeave(val); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) endpointUpdate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	val, exists := vars["endpointID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty endpoint id"))
		return
	}
	var opts types.EPOpts
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

func (router *Router) endpointGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	epID, exists := vars["endpointID"]
	if !exists {
		processServerError(w, r, errors.New("server received empty endpoint id"))
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

func (router *Router) allocateIPv6(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ipamType, exists := vars["ipam-type"]
	if !exists {
		processServerError(w, r, errors.New("server received empty ipam-type"))
		return
	}
	var opts types.IPAMReq
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		processServerError(w, r, err)
		return
	}
	ipamConfig, err := router.daemon.AllocateIP(types.IPAMType(ipamType), opts)
	if err != nil {
		processServerError(w, r, err)
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
	var opts types.IPAMReq
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		processServerError(w, r, err)
		return
	}
	if err := router.daemon.ReleaseIP(types.IPAMType(ipamType), opts); err != nil {
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
	secCtxLabels, _, err := router.daemon.PutLabels(labels)
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
	if err := router.daemon.DeleteLabelsByUUID(uint32(id)); err != nil {
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
	if err := router.daemon.DeleteLabelsBySHA256(sha256sum); err != nil {
		processServerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) getMaxUUID(w http.ResponseWriter, r *http.Request) {
	id, err := router.daemon.GetMaxID()
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
