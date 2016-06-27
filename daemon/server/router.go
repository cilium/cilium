package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/noironetworks/cilium-net/common/backend"
	"github.com/noironetworks/cilium-net/common/types"
	"github.com/noironetworks/cilium-net/daemon/daemon"

	"github.com/gorilla/mux"
)

// Router represents the cilium router to send proper HTTP requests to the daemon.
type routerCommon struct {
	*mux.Router
	routes routes
}

type RouterUI struct {
	routerCommon
	daemon *daemon.Daemon
}

type RouterBackend struct {
	routerCommon
	daemon backend.CiliumBackend
}

// NewRouter creates and returns a new router for the given backend.
func NewRouter(backend backend.CiliumBackend) RouterBackend {
	mRouter := mux.NewRouter().StrictSlash(true)
	r := RouterBackend{routerCommon{mRouter, routes{}}, backend}
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

// NewUIRouter creates and returns a new router only for the UI.
func NewUIRouter(daemon *daemon.Daemon) RouterUI {
	mRouter := mux.NewRouter().StrictSlash(true)
	r := RouterUI{routerCommon{mRouter, routes{}}, daemon}
	r.initUIRoutes()
	for _, route := range r.routes {
		handler := Logger(route.HandlerFunc, route.Name)

		r.Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
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
