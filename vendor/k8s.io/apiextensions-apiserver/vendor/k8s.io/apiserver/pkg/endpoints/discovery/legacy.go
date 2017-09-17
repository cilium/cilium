/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package discovery

import (
	"errors"
	"net/http"

	"github.com/emicklei/go-restful"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/endpoints/handlers/negotiation"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
)

// legacyRootAPIHandler creates a webservice serving api group discovery.
type legacyRootAPIHandler struct {
	// addresses is used to build cluster IPs for discovery.
	addresses     Addresses
	apiPrefix     string
	serializer    runtime.NegotiatedSerializer
	apiVersions   []string
	contextMapper request.RequestContextMapper
}

func NewLegacyRootAPIHandler(addresses Addresses, serializer runtime.NegotiatedSerializer, apiPrefix string, apiVersions []string, contextMapper request.RequestContextMapper) *legacyRootAPIHandler {
	// Because in release 1.1, /apis returns response with empty APIVersion, we
	// use stripVersionNegotiatedSerializer to keep the response backwards
	// compatible.
	serializer = stripVersionNegotiatedSerializer{serializer}

	return &legacyRootAPIHandler{
		addresses:     addresses,
		apiPrefix:     apiPrefix,
		serializer:    serializer,
		apiVersions:   apiVersions,
		contextMapper: contextMapper,
	}
}

// AddApiWebService adds a service to return the supported api versions at the legacy /api.
func (s *legacyRootAPIHandler) WebService() *restful.WebService {
	mediaTypes, _ := negotiation.MediaTypesForSerializer(s.serializer)
	ws := new(restful.WebService)
	ws.Path(s.apiPrefix)
	ws.Doc("get available API versions")
	ws.Route(ws.GET("/").To(s.handle).
		Doc("get available API versions").
		Operation("getAPIVersions").
		Produces(mediaTypes...).
		Consumes(mediaTypes...).
		Writes(metav1.APIVersions{}))
	return ws
}

func (s *legacyRootAPIHandler) handle(req *restful.Request, resp *restful.Response) {
	ctx, ok := s.contextMapper.Get(req.Request)
	if !ok {
		responsewriters.InternalError(resp.ResponseWriter, req.Request, errors.New("no context found for request"))
		return
	}

	clientIP := utilnet.GetClientIP(req.Request)
	apiVersions := &metav1.APIVersions{
		ServerAddressByClientCIDRs: s.addresses.ServerAddressByClientCIDRs(clientIP),
		Versions:                   s.apiVersions,
	}

	responsewriters.WriteObjectNegotiated(ctx, s.serializer, schema.GroupVersion{}, resp.ResponseWriter, req.Request, http.StatusOK, apiVersions)
}
