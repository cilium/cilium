package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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
	if val, ok := vars["uuid"]; !ok {
		processServerError(w, r, errors.New("server received empty uuid"))
		return
	} else {
		if err := router.daemon.EndpointLeave(val); err != nil {
			processServerError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
