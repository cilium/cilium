// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"log/slog"
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type AdminDisableHandler struct {
	logger *slog.Logger
	name   string
}

func NewAdminDisableHandler(logger *slog.Logger, name string) *AdminDisableHandler {
	return &AdminDisableHandler{
		logger: logger.With(subsysLogAttr...),
		name:   name,
	}
}

func (a *AdminDisableHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	wr.WriteHeader(http.StatusForbidden)
	a.logger.Info(
		"Denied API request on administratively disabled API endpoint",
		logfields.Endpoint, a.name,
	)
	_, _ = wr.Write([]byte("This API is administratively disabled in the current configuration of this component. To use it, enable the feature that provides this API in the Cilium configuration and restart the component. If the API is intentionally disabled, no action is needed."))
}

// DisableAPIs configures the API middleware for all of the paths in the
// provided PathSet such that those APIs will be administratively disabled at
// runtime.
func DisableAPIs(logger *slog.Logger, paths PathSet, addMiddleware func(method string, path string, builder middleware.Builder)) {
	for k, pm := range paths {
		addMiddleware(pm.Method, pm.Path, func(_ http.Handler) http.Handler {
			return NewAdminDisableHandler(logger, k)
		})
	}
}
