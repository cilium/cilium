package server

import (
	"net/http"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

func (r *Router) initRoutes() {
	r.routes = Routes{
		Route{
			"Ping", "GET", "/ping", r.ping,
		},
		Route{
			"EndpointCreate", "POST", "/endpoint/{uuid}", r.endpointCreate,
		},
		Route{
			"EndpointDelete", "DELETE", "/endpoint/{uuid}", r.endpointDelete,
		},
	}
}
