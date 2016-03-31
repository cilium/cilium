package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/noironetworks/cilium-net/common/types"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/gorilla/mux"
)

func (router *Router) ping(w http.ResponseWriter, r *http.Request) {
	if str, err := router.daemon.Ping(); err != nil {
		processServerError(w, r, err)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, str)
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
	if val, ok := vars["endpointID"]; !ok {
		processServerError(w, r, errors.New("server received empty endpoint id"))
		return
	} else {
		if err := router.daemon.EndpointLeave(val); err != nil {
			processServerError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (router *Router) allocateIPv6(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if containerID, ok := vars["containerID"]; !ok {
		processServerError(w, r, errors.New("server received empty containerID"))
		return
	} else {
		ipamConfig, err := router.daemon.AllocateIPs(containerID)
		if err != nil {
			processServerError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		e := json.NewEncoder(w)
		if err := e.Encode(ipamConfig); err != nil {
			processServerError(w, r, err)
			return
		}
	}
}

func (router *Router) releaseIPv6(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if containerID, ok := vars["containerID"]; !ok {
		processServerError(w, r, errors.New("server received empty containerID"))
		return
	} else {
		if err := router.daemon.ReleaseIPs(containerID); err != nil {
			processServerError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (router *Router) getLabels(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr, exists := vars["uuid"]
	if !exists {
		processServerError(w, r, errors.New("server received empty labels UUID"))
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		processServerError(w, r, fmt.Errorf("server received invalid UUID '%s': '%s'", idStr, err))
		return
	}
	labels, err := router.daemon.GetLabels(id)
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
	id, err := strconv.Atoi(idStr)
	if err != nil {
		processServerError(w, r, fmt.Errorf("server received invalid UUID '%s': '%s'", idStr, err))
		return
	}
	if err := router.daemon.DeleteLabelsByUUID(id); err != nil {
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
	if err := router.daemon.PolicyAdd(path, pn); err != nil {
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
