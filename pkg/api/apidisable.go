// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"log/slog"
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type AdminDisableHandler struct {
	logger logging.FieldLogger
	name   string
}

func NewAdminDisableHandler(logger logging.FieldLogger, name string) *AdminDisableHandler {
	return &AdminDisableHandler{
		logger: logger,
		name:   name,
	}
}

func (a *AdminDisableHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	wr.WriteHeader(http.StatusForbidden)
	a.logger.Info(
		"Denied API request on administratively disabled API endpoint",
		slog.String(logfields.Endpoint, a.name),
	)
	_, _ = wr.Write([]byte("This API is administratively disabled. Contact your administrator for more details."))
}

// DisableAPIs configures the API middleware for all of the paths in the
// provided PathSet such that those APIs will be administratively disabled at
// runtime.
func DisableAPIs(logger logging.FieldLogger, paths PathSet, addMiddleware func(method string, path string, builder middleware.Builder)) {
	for k, pm := range paths {
		addMiddleware(pm.Method, pm.Path, func(_ http.Handler) http.Handler {
			return NewAdminDisableHandler(logger, k)
		})
	}
}
