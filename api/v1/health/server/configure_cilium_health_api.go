// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This file is safe to edit. Once it exists it will not be overwritten

package server

import (
	"crypto/tls"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/health/server/restapi"
	"github.com/cilium/cilium/api/v1/health/server/restapi/connectivity"
)

//go:generate swagger generate server --target ../../health --name CiliumHealthAPI --spec ../openapi.yaml --api-package restapi --server-package server --principal interface{} --default-scheme unix

func configureFlags(api *restapi.CiliumHealthAPIAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *restapi.CiliumHealthAPIAPI) http.Handler {
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

	if api.GetHealthzHandler == nil {
		api.GetHealthzHandler = restapi.GetHealthzHandlerFunc(func(params restapi.GetHealthzParams) middleware.Responder {
			return middleware.NotImplemented("operation restapi.GetHealthz has not yet been implemented")
		})
	}
	if api.ConnectivityGetStatusHandler == nil {
		api.ConnectivityGetStatusHandler = connectivity.GetStatusHandlerFunc(func(params connectivity.GetStatusParams) middleware.Responder {
			return middleware.NotImplemented("operation connectivity.GetStatus has not yet been implemented")
		})
	}
	if api.ConnectivityPutStatusProbeHandler == nil {
		api.ConnectivityPutStatusProbeHandler = connectivity.PutStatusProbeHandlerFunc(func(params connectivity.PutStatusProbeParams) middleware.Responder {
			return middleware.NotImplemented("operation connectivity.PutStatusProbe has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
