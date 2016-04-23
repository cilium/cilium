package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noironetworks/cilium-net/common/backend"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/gorilla/mux"
)

// Router represents the cilium router to send proper HTTP requests to the daemon.
type Router struct {
	*mux.Router
	daemon backend.CiliumBackend
	routes routes
}

// NewRouter creates and returns a new router for the given backend.
func NewRouter(backend backend.CiliumBackend) Router {
	mRouter := mux.NewRouter().StrictSlash(true)
	r := Router{mRouter, backend, routes{}}
	r.initRoutes()
	for _, route := range r.routes {
		handler := Logger(route.HandlerFunc, route.Name)

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
	sErr := types.ServerError{
		Code: http.StatusInternalServerError,
		Text: fmt.Sprintf("an unexpected internal error has occurred: \"%s\"", err),
	}
	log.Debugf("Processing error %s\n", sErr)
	log.Errorf("Error while processing request '%+v': \"%s\"", r, err)
	if err := json.NewEncoder(w).Encode(sErr); err != nil {
		log.Errorf("Error while encoding %T '%+v': \"%s\"", sErr, sErr, err)
		fmt.Fprintf(w, "Fatal error while processing request '%+v': \"%s\"", r, err)
	}
}
