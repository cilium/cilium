// Copyright 2015 Google Inc. All Rights Reserved.
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

package http

import (
	"fmt"
	"net/http"
	"os"

	"github.com/google/cadvisor/api"
	"github.com/google/cadvisor/healthz"
	httpmux "github.com/google/cadvisor/http/mux"
	"github.com/google/cadvisor/manager"
	"github.com/google/cadvisor/metrics"
	"github.com/google/cadvisor/pages"
	"github.com/google/cadvisor/pages/static"
	"github.com/google/cadvisor/validate"

	auth "github.com/abbot/go-http-auth"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func RegisterHandlers(mux httpmux.Mux, containerManager manager.Manager, httpAuthFile, httpAuthRealm, httpDigestFile, httpDigestRealm string) error {
	// Basic health handler.
	if err := healthz.RegisterHandler(mux); err != nil {
		return fmt.Errorf("failed to register healthz handler: %s", err)
	}

	// Validation/Debug handler.
	mux.HandleFunc(validate.ValidatePage, func(w http.ResponseWriter, r *http.Request) {
		err := validate.HandleRequest(w, containerManager)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Register API handler.
	if err := api.RegisterHandlers(mux, containerManager); err != nil {
		return fmt.Errorf("failed to register API handlers: %s", err)
	}

	// Redirect / to containers page.
	mux.Handle("/", http.RedirectHandler(pages.ContainersPage, http.StatusTemporaryRedirect))

	var authenticated bool

	// Setup the authenticator object
	if httpAuthFile != "" {
		glog.Infof("Using auth file %s", httpAuthFile)
		secrets := auth.HtpasswdFileProvider(httpAuthFile)
		authenticator := auth.NewBasicAuthenticator(httpAuthRealm, secrets)
		mux.HandleFunc(static.StaticResource, authenticator.Wrap(staticHandler))
		if err := pages.RegisterHandlersBasic(mux, containerManager, authenticator); err != nil {
			return fmt.Errorf("failed to register pages auth handlers: %s", err)
		}
		authenticated = true
	}
	if httpAuthFile == "" && httpDigestFile != "" {
		glog.Infof("Using digest file %s", httpDigestFile)
		secrets := auth.HtdigestFileProvider(httpDigestFile)
		authenticator := auth.NewDigestAuthenticator(httpDigestRealm, secrets)
		mux.HandleFunc(static.StaticResource, authenticator.Wrap(staticHandler))
		if err := pages.RegisterHandlersDigest(mux, containerManager, authenticator); err != nil {
			return fmt.Errorf("failed to register pages digest handlers: %s", err)
		}
		authenticated = true
	}

	// Change handler based on authenticator initalization
	if !authenticated {
		mux.HandleFunc(static.StaticResource, staticHandlerNoAuth)
		if err := pages.RegisterHandlersBasic(mux, containerManager, nil); err != nil {
			return fmt.Errorf("failed to register pages handlers: %s", err)
		}
	}

	return nil
}

// RegisterPrometheusHandler creates a new PrometheusCollector and configures
// the provided HTTP mux to handle the given Prometheus endpoint.
func RegisterPrometheusHandler(mux httpmux.Mux, containerManager manager.Manager, prometheusEndpoint string, f metrics.ContainerLabelsFunc) {
	r := prometheus.NewRegistry()
	r.MustRegister(
		metrics.NewPrometheusCollector(containerManager, f),
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(os.Getpid(), ""),
	)
	mux.Handle(prometheusEndpoint, promhttp.HandlerFor(r, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}))
}

func staticHandlerNoAuth(w http.ResponseWriter, r *http.Request) {
	static.HandleRequest(w, r.URL)
}

func staticHandler(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	static.HandleRequest(w, r.URL)
}
