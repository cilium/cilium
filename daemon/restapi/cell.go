// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"github.com/sirupsen/logrus"

	ciliumServer "github.com/cilium/cilium/api/v1/server"
	ciliumAPI "github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/api/server"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the Cilium API specification and utilities.
var Cell = cell.Module(
	"cilium-restapi",
	"Cilium Agent API",

	// Request rate-limiting
	rateLimiterCell,

	// Cilium API Specification
	ciliumServer.SpecCell,
)

// ServerCell provides the API server. Split from Cell for integration
// testing.
var ServerCell = cell.Module(
	"cilium-restapi-server",
	"Cilium Agent API Server",

	// Cilium API type with handlers filled in
	ciliumServer.APICell,

	// API server for Swagger and gRPC served over a unix socket.
	// Accessed by cilium-dbg.
	server.Cell,

	cell.Invoke(configureAPIServer),
)

func configureAPIServer(log logrus.FieldLogger, cfg *option.DaemonConfig, s *server.Server, ciliumAPI *ciliumAPI.CiliumAPIAPI, swaggerSpec *ciliumServer.Spec) {
	// Configure disabled APIs
	msg := "Required API option %s is disabled. This may prevent Cilium from operating correctly"
	hint := "Consider enabling this API in " + ciliumServer.AdminEnableFlag
	for _, requiredAPI := range []string{
		"GetConfig",        // CNI: Used to detect detect IPAM mode
		"GetHealthz",       // Kubelet: daemon health checks
		"PutEndpointID",    // CNI: Provision the network for a new Pod
		"DeleteEndpointID", // CNI: Clean up networking for a deleted Pod
		"PostIPAM",         // CNI: Reserve IPs for new Pods
		"DeleteIPAMIP",     // CNI: Release IPs for deleted Pods
	} {
		if _, denied := swaggerSpec.DeniedAPIs[requiredAPI]; denied {
			log.WithFields(logrus.Fields{
				logfields.Hint:   hint,
				logfields.Params: requiredAPI,
			}).Warning(msg)
		}
	}
	api.DisableAPIs(swaggerSpec.DeniedAPIs, ciliumAPI.AddMiddlewareFor)

	// Set the swagger API as the fallback after gRPC.
	s.SetFallbackHandler(ciliumAPI.Serve(nil))
}
