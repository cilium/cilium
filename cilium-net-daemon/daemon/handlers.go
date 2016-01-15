package cilium_net_daemon

import (
	"fmt"
	"net/http"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/gorilla/mux"
)

func Ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Pong\n")
}

func EndpointCreate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	//compile eBPF program
	log.Debug("vars[\"uuid\"]=", vars["uuid"])
	w.WriteHeader(http.StatusNotImplemented)
}

func EndpointDelete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Debug("vars[\"uuid\"]=", vars["uuid"])
	w.WriteHeader(http.StatusNotImplemented)
}

func EndpointGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	log.Debug("vars[\"uuid\"]=", vars["uuid"])
	w.WriteHeader(http.StatusNotImplemented)
}
