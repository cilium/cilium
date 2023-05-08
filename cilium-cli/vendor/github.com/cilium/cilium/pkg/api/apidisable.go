// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type AdminDisableHandler struct {
	name string
}

func NewAdminDisableHandler(name string) *AdminDisableHandler {
	return &AdminDisableHandler{
		name: name,
	}
}

func (a *AdminDisableHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	wr.WriteHeader(http.StatusForbidden)
	log.WithFields(logrus.Fields{
		logfields.Endpoint: a.name,
	}).Info("Denied API request on administratively disabled API endpoint")
	_, _ = wr.Write([]byte("This API is administratively disabled. Contact your administrator for more details."))
}

// DisableAPIs configures the API middleware for all of the paths in the
// provided PathSet such that those APIs will be administratively disabled at
// runtime.
func DisableAPIs(paths PathSet, addMiddleware func(method, path string, builder middleware.Builder)) {
	for k, pm := range paths {
		addMiddleware(pm.Method, pm.Path, func(_ http.Handler) http.Handler {
			return NewAdminDisableHandler(k)
		})
	}
}
