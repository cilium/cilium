// Copyright 2018 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"

	"google.golang.org/protobuf/encoding/protojson"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

// HTTPGateway is a custom implementation of [gRPC gateway](https://github.com/grpc-ecosystem/grpc-gateway)
// specialized to Envoy xDS API.
type HTTPGateway struct {
	// Server is the underlying gRPC server
	Server Server
}

func (h *HTTPGateway) ServeHTTP(req *http.Request) ([]byte, int, error) {
	p := path.Clean(req.URL.Path)

	typeURL := ""
	switch p {
	case resource.FetchEndpoints:
		typeURL = resource.EndpointType
	case resource.FetchClusters:
		typeURL = resource.ClusterType
	case resource.FetchListeners:
		typeURL = resource.ListenerType
	case resource.FetchRoutes:
		typeURL = resource.RouteType
	case resource.FetchScopedRoutes:
		typeURL = resource.ScopedRouteType
	case resource.FetchSecrets:
		typeURL = resource.SecretType
	case resource.FetchRuntimes:
		typeURL = resource.RuntimeType
	case resource.FetchExtensionConfigs:
		typeURL = resource.ExtensionConfigType
	default:
		return nil, http.StatusNotFound, errors.New("no endpoint")
	}

	if req.Body == nil {
		return nil, http.StatusBadRequest, errors.New("empty body")
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, http.StatusBadRequest, errors.New("cannot read body")
	}

	// parse as JSON
	out := &discovery.DiscoveryRequest{}
	err = protojson.Unmarshal(body, out)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("cannot parse JSON body: %w", err)
	}
	out.TypeUrl = typeURL

	// fetch results
	res, err := h.Server.Fetch(req.Context(), out)
	if err != nil {
		// SkipFetchErrors will return a 304 which will signify to the envoy client that
		// it is already at the latest version; all other errors will 500 with a message.
		var skip *types.SkipFetchError
		if ok := errors.As(err, &skip); ok {
			return nil, http.StatusNotModified, nil
		}
		return nil, http.StatusInternalServerError, fmt.Errorf("fetch error: %w", err)
	}

	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(res)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("marshal error: %w", err)
	}

	return b, http.StatusOK, nil
}
