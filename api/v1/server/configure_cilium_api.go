// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file is safe to edit. Once it exists it will not be overwritten

package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/api/v1/server/restapi/ipam"
	"github.com/cilium/cilium/api/v1/server/restapi/metrics"
	"github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/api/v1/server/restapi/prefilter"
	"github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/logging"
	ciliumMetrics "github.com/cilium/cilium/pkg/metrics"
)

//go:generate swagger generate server --target ../../v1 --name CiliumAPI --spec ../openapi.yaml --api-package restapi --server-package server --principal interface{} --default-scheme unix

func configureFlags(api *restapi.CiliumAPIAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *restapi.CiliumAPIAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	// api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	if api.EndpointDeleteEndpointIDHandler == nil {
		api.EndpointDeleteEndpointIDHandler = endpoint.DeleteEndpointIDHandlerFunc(func(params endpoint.DeleteEndpointIDParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.DeleteEndpointID has not yet been implemented")
		})
	}
	if api.PolicyDeleteFqdnCacheHandler == nil {
		api.PolicyDeleteFqdnCacheHandler = policy.DeleteFqdnCacheHandlerFunc(func(params policy.DeleteFqdnCacheParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.DeleteFqdnCache has not yet been implemented")
		})
	}
	if api.IpamDeleteIpamIPHandler == nil {
		api.IpamDeleteIpamIPHandler = ipam.DeleteIpamIPHandlerFunc(func(params ipam.DeleteIpamIPParams) middleware.Responder {
			return middleware.NotImplemented("operation ipam.DeleteIpamIP has not yet been implemented")
		})
	}
	if api.PolicyDeletePolicyHandler == nil {
		api.PolicyDeletePolicyHandler = policy.DeletePolicyHandlerFunc(func(params policy.DeletePolicyParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.DeletePolicy has not yet been implemented")
		})
	}
	if api.PrefilterDeletePrefilterHandler == nil {
		api.PrefilterDeletePrefilterHandler = prefilter.DeletePrefilterHandlerFunc(func(params prefilter.DeletePrefilterParams) middleware.Responder {
			return middleware.NotImplemented("operation prefilter.DeletePrefilter has not yet been implemented")
		})
	}
	if api.ServiceDeleteServiceIDHandler == nil {
		api.ServiceDeleteServiceIDHandler = service.DeleteServiceIDHandlerFunc(func(params service.DeleteServiceIDParams) middleware.Responder {
			return middleware.NotImplemented("operation service.DeleteServiceID has not yet been implemented")
		})
	}
	if api.DaemonGetClusterNodesHandler == nil {
		api.DaemonGetClusterNodesHandler = daemon.GetClusterNodesHandlerFunc(func(params daemon.GetClusterNodesParams) middleware.Responder {
			return middleware.NotImplemented("operation daemon.GetClusterNodes has not yet been implemented")
		})
	}
	if api.DaemonGetConfigHandler == nil {
		api.DaemonGetConfigHandler = daemon.GetConfigHandlerFunc(func(params daemon.GetConfigParams) middleware.Responder {
			return middleware.NotImplemented("operation daemon.GetConfig has not yet been implemented")
		})
	}
	if api.DaemonGetDebuginfoHandler == nil {
		api.DaemonGetDebuginfoHandler = daemon.GetDebuginfoHandlerFunc(func(params daemon.GetDebuginfoParams) middleware.Responder {
			return middleware.NotImplemented("operation daemon.GetDebuginfo has not yet been implemented")
		})
	}
	if api.EndpointGetEndpointHandler == nil {
		api.EndpointGetEndpointHandler = endpoint.GetEndpointHandlerFunc(func(params endpoint.GetEndpointParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.GetEndpoint has not yet been implemented")
		})
	}
	if api.EndpointGetEndpointIDHandler == nil {
		api.EndpointGetEndpointIDHandler = endpoint.GetEndpointIDHandlerFunc(func(params endpoint.GetEndpointIDParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.GetEndpointID has not yet been implemented")
		})
	}
	if api.EndpointGetEndpointIDConfigHandler == nil {
		api.EndpointGetEndpointIDConfigHandler = endpoint.GetEndpointIDConfigHandlerFunc(func(params endpoint.GetEndpointIDConfigParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.GetEndpointIDConfig has not yet been implemented")
		})
	}
	if api.EndpointGetEndpointIDHealthzHandler == nil {
		api.EndpointGetEndpointIDHealthzHandler = endpoint.GetEndpointIDHealthzHandlerFunc(func(params endpoint.GetEndpointIDHealthzParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.GetEndpointIDHealthz has not yet been implemented")
		})
	}
	if api.EndpointGetEndpointIDLabelsHandler == nil {
		api.EndpointGetEndpointIDLabelsHandler = endpoint.GetEndpointIDLabelsHandlerFunc(func(params endpoint.GetEndpointIDLabelsParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.GetEndpointIDLabels has not yet been implemented")
		})
	}
	if api.EndpointGetEndpointIDLogHandler == nil {
		api.EndpointGetEndpointIDLogHandler = endpoint.GetEndpointIDLogHandlerFunc(func(params endpoint.GetEndpointIDLogParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.GetEndpointIDLog has not yet been implemented")
		})
	}
	if api.PolicyGetFqdnCacheHandler == nil {
		api.PolicyGetFqdnCacheHandler = policy.GetFqdnCacheHandlerFunc(func(params policy.GetFqdnCacheParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetFqdnCache has not yet been implemented")
		})
	}
	if api.PolicyGetFqdnCacheIDHandler == nil {
		api.PolicyGetFqdnCacheIDHandler = policy.GetFqdnCacheIDHandlerFunc(func(params policy.GetFqdnCacheIDParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetFqdnCacheID has not yet been implemented")
		})
	}
	if api.PolicyGetFqdnNamesHandler == nil {
		api.PolicyGetFqdnNamesHandler = policy.GetFqdnNamesHandlerFunc(func(params policy.GetFqdnNamesParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetFqdnNames has not yet been implemented")
		})
	}
	if api.DaemonGetHealthzHandler == nil {
		api.DaemonGetHealthzHandler = daemon.GetHealthzHandlerFunc(func(params daemon.GetHealthzParams) middleware.Responder {
			return middleware.NotImplemented("operation daemon.GetHealthz has not yet been implemented")
		})
	}
	if api.PolicyGetIPHandler == nil {
		api.PolicyGetIPHandler = policy.GetIPHandlerFunc(func(params policy.GetIPParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetIP has not yet been implemented")
		})
	}
	if api.PolicyGetIdentityHandler == nil {
		api.PolicyGetIdentityHandler = policy.GetIdentityHandlerFunc(func(params policy.GetIdentityParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetIdentity has not yet been implemented")
		})
	}
	if api.PolicyGetIdentityEndpointsHandler == nil {
		api.PolicyGetIdentityEndpointsHandler = policy.GetIdentityEndpointsHandlerFunc(func(params policy.GetIdentityEndpointsParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetIdentityEndpoints has not yet been implemented")
		})
	}
	if api.PolicyGetIdentityIDHandler == nil {
		api.PolicyGetIdentityIDHandler = policy.GetIdentityIDHandlerFunc(func(params policy.GetIdentityIDParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetIdentityID has not yet been implemented")
		})
	}
	if api.DaemonGetMapHandler == nil {
		api.DaemonGetMapHandler = daemon.GetMapHandlerFunc(func(params daemon.GetMapParams) middleware.Responder {
			return middleware.NotImplemented("operation daemon.GetMap has not yet been implemented")
		})
	}
	if api.DaemonGetMapNameHandler == nil {
		api.DaemonGetMapNameHandler = daemon.GetMapNameHandlerFunc(func(params daemon.GetMapNameParams) middleware.Responder {
			return middleware.NotImplemented("operation daemon.GetMapName has not yet been implemented")
		})
	}
	if api.MetricsGetMetricsHandler == nil {
		api.MetricsGetMetricsHandler = metrics.GetMetricsHandlerFunc(func(params metrics.GetMetricsParams) middleware.Responder {
			return middleware.NotImplemented("operation metrics.GetMetrics has not yet been implemented")
		})
	}
	if api.PolicyGetPolicyHandler == nil {
		api.PolicyGetPolicyHandler = policy.GetPolicyHandlerFunc(func(params policy.GetPolicyParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetPolicy has not yet been implemented")
		})
	}
	if api.PolicyGetPolicySelectorsHandler == nil {
		api.PolicyGetPolicySelectorsHandler = policy.GetPolicySelectorsHandlerFunc(func(params policy.GetPolicySelectorsParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.GetPolicySelectors has not yet been implemented")
		})
	}
	if api.PrefilterGetPrefilterHandler == nil {
		api.PrefilterGetPrefilterHandler = prefilter.GetPrefilterHandlerFunc(func(params prefilter.GetPrefilterParams) middleware.Responder {
			return middleware.NotImplemented("operation prefilter.GetPrefilter has not yet been implemented")
		})
	}
	if api.ServiceGetServiceHandler == nil {
		api.ServiceGetServiceHandler = service.GetServiceHandlerFunc(func(params service.GetServiceParams) middleware.Responder {
			return middleware.NotImplemented("operation service.GetService has not yet been implemented")
		})
	}
	if api.ServiceGetServiceIDHandler == nil {
		api.ServiceGetServiceIDHandler = service.GetServiceIDHandlerFunc(func(params service.GetServiceIDParams) middleware.Responder {
			return middleware.NotImplemented("operation service.GetServiceID has not yet been implemented")
		})
	}
	if api.DaemonPatchConfigHandler == nil {
		api.DaemonPatchConfigHandler = daemon.PatchConfigHandlerFunc(func(params daemon.PatchConfigParams) middleware.Responder {
			return middleware.NotImplemented("operation daemon.PatchConfig has not yet been implemented")
		})
	}
	if api.EndpointPatchEndpointIDHandler == nil {
		api.EndpointPatchEndpointIDHandler = endpoint.PatchEndpointIDHandlerFunc(func(params endpoint.PatchEndpointIDParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.PatchEndpointID has not yet been implemented")
		})
	}
	if api.EndpointPatchEndpointIDConfigHandler == nil {
		api.EndpointPatchEndpointIDConfigHandler = endpoint.PatchEndpointIDConfigHandlerFunc(func(params endpoint.PatchEndpointIDConfigParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.PatchEndpointIDConfig has not yet been implemented")
		})
	}
	if api.EndpointPatchEndpointIDLabelsHandler == nil {
		api.EndpointPatchEndpointIDLabelsHandler = endpoint.PatchEndpointIDLabelsHandlerFunc(func(params endpoint.PatchEndpointIDLabelsParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.PatchEndpointIDLabels has not yet been implemented")
		})
	}
	if api.PrefilterPatchPrefilterHandler == nil {
		api.PrefilterPatchPrefilterHandler = prefilter.PatchPrefilterHandlerFunc(func(params prefilter.PatchPrefilterParams) middleware.Responder {
			return middleware.NotImplemented("operation prefilter.PatchPrefilter has not yet been implemented")
		})
	}
	if api.IpamPostIpamHandler == nil {
		api.IpamPostIpamHandler = ipam.PostIpamHandlerFunc(func(params ipam.PostIpamParams) middleware.Responder {
			return middleware.NotImplemented("operation ipam.PostIpam has not yet been implemented")
		})
	}
	if api.IpamPostIpamIPHandler == nil {
		api.IpamPostIpamIPHandler = ipam.PostIpamIPHandlerFunc(func(params ipam.PostIpamIPParams) middleware.Responder {
			return middleware.NotImplemented("operation ipam.PostIpamIP has not yet been implemented")
		})
	}
	if api.EndpointPutEndpointIDHandler == nil {
		api.EndpointPutEndpointIDHandler = endpoint.PutEndpointIDHandlerFunc(func(params endpoint.PutEndpointIDParams) middleware.Responder {
			return middleware.NotImplemented("operation endpoint.PutEndpointID has not yet been implemented")
		})
	}
	if api.PolicyPutPolicyHandler == nil {
		api.PolicyPutPolicyHandler = policy.PutPolicyHandlerFunc(func(params policy.PutPolicyParams) middleware.Responder {
			return middleware.NotImplemented("operation policy.PutPolicy has not yet been implemented")
		})
	}
	if api.ServicePutServiceIDHandler == nil {
		api.ServicePutServiceIDHandler = service.PutServiceIDHandlerFunc(func(params service.PutServiceIDParams) middleware.Responder {
			return middleware.NotImplemented("operation service.PutServiceID has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {
		logging.DefaultLogger.Debug("canceling server context")
		serverCancel()
	}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

var (
	// ServerCtx and ServerCancel
	ServerCtx, serverCancel = context.WithCancel(context.Background())
)

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
	s.BaseContext = func(_ net.Listener) context.Context {
		return ServerCtx
	}
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	eventsHelper := &ciliumMetrics.APIEventTSHelper{
		Next:      handler,
		TSGauge:   ciliumMetrics.EventTS,
		Histogram: ciliumMetrics.APIInteractions,
	}

	return &api.APIPanicHandler{
		Next: eventsHelper,
	}
}
