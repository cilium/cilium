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
			"GlobalStatus", "GET", "/healthz", r.globalStatus,
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
			"EndpointGetByDockerID", "GET", "/endpoint-by-docker-id/{dockerID}", r.endpointGetByDockerID,
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
		route{
			"ServiceAdd", "POST", "/lb/service", r.serviceAdd,
		},
		route{
			"ServiceDel", "DELETE", "/lb/service/{feSHA256Sum}", r.serviceDel,
		},
		route{
			"ServiceGet", "GET", "/lb/service/{feSHA256Sum}", r.serviceGet,
		},
		route{
			"ServiceDump", "GET", "/lb/services", r.serviceDump,
		},
		route{
			"RevNATAdd", "POST", "/lb/revnat", r.revNATAdd,
		},
		route{
			"RevNATDel", "DELETE", "/lb/revnat/{revNATID}", r.revNATDel,
		},
		route{
			"RevNATGet", "GET", "/lb/revnat/{revNATID}", r.revNATGet,
		},
		route{
			"RevNATDump", "GET", "/lb/revnats", r.revNATDump,
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
