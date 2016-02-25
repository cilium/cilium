package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noironetworks/cilium-net/common/backend"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/gorilla/mux"
)

type Router struct {
	*mux.Router
	daemon backend.CiliumBackend
	routes Routes
}

func NewRouter(d backend.CiliumBackend) Router {
	mrouter := mux.NewRouter().StrictSlash(true)
	r := Router{mrouter, d, Routes{}}
	r.initRoutes()
	for _, route := range r.routes {
		var handler http.Handler

		handler = route.HandlerFunc
		handler = Logger(handler, route.Name)

		r.Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}
	return r
}

func processServerError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	sErr := types.ServerError{
		http.StatusInternalServerError,
		fmt.Sprintf("an unexpected internal error has occurred: \"%s\"", err),
	}
	log.Errorf("Error processing request '%+v': \"%s\"", r, err)
	if err := e.Encode(sErr); err != nil {
		log.Errorf("Error encoding %T '%+v': \"%s\"", sErr, sErr, err)
		fmt.Fprintf(w, "Fatal error processing request '%+v': \"%s\"", r, err)
	}
}
