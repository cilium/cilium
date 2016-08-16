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
	"fmt"
	"net/http"

	"github.com/cilium/cilium/common/backend"
	"github.com/cilium/cilium/common/types"

	"github.com/gorilla/mux"
)

// Router represents the cilium router to send proper HTTP requests to the daemon.
type Router struct {
	*mux.Router
	routes routes
	daemon backend.CiliumDaemonBackend
}

// NewRouter creates and returns a new router for the given backend.
func NewRouter(daemon backend.CiliumDaemonBackend) Router {
	mRouter := mux.NewRouter().StrictSlash(true)
	r := Router{mRouter, routes{}, daemon}
	r.initBackendRoutes()
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
func NewUIRouter(daemon backend.CiliumDaemonBackend) Router {
	mRouter := mux.NewRouter().StrictSlash(true)
	r := Router{mRouter, routes{}, daemon}
	r.initUIRoutes()
	for _, route := range r.routes {
		handler := Logger(route.HandlerFunc, route.Name)

		r.Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	uiDir, _ := daemon.GetUIPath()
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(uiDir))))
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
