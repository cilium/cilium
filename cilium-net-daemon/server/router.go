package server

import (
	"net/http"

	"github.com/noironetworks/cilium-net/common/backend"

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
