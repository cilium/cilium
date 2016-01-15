package cilium_net_daemon

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

var routes = Routes{
	Route{
		"Ping", "GET", "/ping", Ping,
	},
	Route{
		"EndpointCreate", "POST", "/endpoint/{uuid}", EndpointCreate,
	},
	Route{
		"EndpointDelete", "DELETE", "/endpoint/{uuid}", EndpointDelete,
	},
	Route{
		"EndpointGet", "GET", "/endpoint/{uuid}", EndpointGet,
	},
}
