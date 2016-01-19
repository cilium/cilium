package server

import (
	"fmt"
	"net/http"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/gorilla/mux"
)

func (router *Router) ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	str, _ := router.daemon.Ping()
	fmt.Fprint(w, str)
}

func (router *Router) endpointCreate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	//compile eBPF program
	log.Debug("vars[\"uuid\"]=", vars["uuid"])
	w.WriteHeader(http.StatusNotImplemented)
}

func (router *Router) endpointDelete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Debug("vars[\"uuid\"]=", vars["uuid"])
	w.WriteHeader(http.StatusNotImplemented)
}

func (router *Router) endpointGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Debug("vars[\"uuid\"]=", vars["uuid"])
	w.WriteHeader(http.StatusNotImplemented)
}
