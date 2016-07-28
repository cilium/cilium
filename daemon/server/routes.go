package server

import (
	"net/http"
)

type route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type routes []route

func (r *Router) initBackendRoutes() {
	r.routes = routes{
		route{
			"Ping", "GET", "/ping", r.ping,
		},
		route{
			"Update", "POST", "/update", r.update,
		},
		route{
			"EndpointCreate", "POST", "/endpoint/{endpointID}", r.endpointCreate,
		},
		route{
			"EndpointDelete", "DELETE", "/endpoint/{endpointID}", r.endpointDelete,
		},
		route{
			"EndpointGetByDockerEPID", "DELETE", "/endpoint-by-docker-ep-id/{dockerEPID}", r.endpointLeaveByDockerEPID,
		},
		route{
			"EndpointGet", "GET", "/endpoint/{endpointID}", r.endpointGet,
		},
		route{
			"EndpointGetByDockerEPID", "GET", "/endpoint-by-docker-ep-id/{dockerEPID}", r.endpointGetByDockerEPID,
		},
		route{
			"EndpointsGet", "GET", "/endpoints", r.endpointsGet,
		},
		route{
			"EndpointUpdate", "POST", "/endpoint/update/{endpointID}", r.endpointUpdate,
		},
		route{
			"EndpointSave", "POST", "/endpoint/save/{endpointID}", r.endpointSave,
		},
		route{
			"EndpointLabelsGet", "GET", "/endpoint/labels/{endpointID}", r.endpointLabelsGet,
		},
		route{
			"EndpointLabelsUpdate", "POST", "/endpoint/labels/{endpointID}", r.endpointLabelsUpdate,
		},
		route{
			"IPAMConfiguration", "POST", "/allocator/ipam-configuration/{ipam-type}", r.ipamConfig,
		},
		route{
			"AllocateIPv6", "POST", "/allocator/ipam-allocate/{ipam-type}", r.allocateIPv6,
		},
		route{
			"ReleaseIPv6", "POST", "/allocator/ipam-release/{ipam-type}", r.releaseIPv6,
		},
		route{
			"GetLabels", "GET", "/labels/by-uuid/{uuid}", r.getLabels,
		},
		route{
			"GetLabelsBySHA256", "GET", "/labels/by-sha256sum/{sha256sum}", r.getLabelsBySHA256,
		},
		route{
			"PutLabels", "POST", "/labels/{contID}", r.putLabels,
		},
		route{
			"DeleteLabelsBySHA256", "DELETE", "/labels/by-sha256sum/{sha256sum}/{contID}", r.deleteLabelsBySHA256,
		},
		route{
			"DeleteLabelsByUUID", "DELETE", "/labels/by-uuid/{uuid}/{contID}", r.deleteLabelsByUUID,
		},
		route{
			"GetMaxID", "GET", "/labels/status/maxUUID", r.getMaxUUID,
		},
		route{
			"PolicyAdd", "POST", "/policy/{path}", r.policyAdd,
		},
		route{
			"PolicyDelete", "DELETE", "/policy/{path}", r.policyDelete,
		},
		route{
			"PolicyGet", "GET", "/policy/{path}", r.policyGet,
		},
		route{
			"PolicyCanConsume", "POST", "/policy-consume-decision", r.policyCanConsume,
		},
	}
}

func (r *Router) initUIRoutes() {
	r.routes = routes{
		route{
			"GetUI", "GET", "/", r.createUIHTMLIndex,
		},
		route{
			"WebSocketUI", "GET", "/ws", r.webSocketUIStats,
		},
		route{
			"EndpointsGet", "GET", "/endpoints", r.endpointsGet,
		},
		route{
			"EndpointUpdate", "POST", "/endpoint/update/{endpointID}", r.endpointUpdate,
		},
		route{
			"Update", "POST", "/update", r.update,
		},
		route{
			"PolicyAdd", "POST", "/policy/{path}", r.policyAddForm,
		},
		route{
			"PolicyGet", "GET", "/policy/{path}", r.policyGet,
		},
		route{
			"EndpointLabelsGet", "GET", "/endpoint/labels/{endpointID}", r.endpointLabelsGet,
		},
		route{
			"EndpointLabelsUpdate", "POST", "/endpoint/labels/{endpointID}", r.endpointLabelsUpdate,
		},
	}
}
