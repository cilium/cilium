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
		Route{
			"AllocateIPv6", "PUT", "/allocator/container/{containerID}", r.allocateIPv6,
		},
		Route{
			"ReleaseIPv6", "DELETE", "/allocator/container/{containerID}", r.releaseIPv6,
		},
		Route{
			"GetLabels", "GET", "/labels/{uuid}", r.getLabels,
		},
		Route{
			"GetLabelsID", "POST", "/labels", r.getLabelsID,
		},
	}
}
