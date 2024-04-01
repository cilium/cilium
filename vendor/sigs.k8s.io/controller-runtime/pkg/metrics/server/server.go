/*
Copyright 2018 The Kubernetes Authors.

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

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"

	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/internal/httpserver"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	defaultMetricsEndpoint = "/metrics"
)

// DefaultBindAddress is the default bind address for the metrics server.
var DefaultBindAddress = ":8080"

// Server is a server that serves metrics.
type Server interface {
	// NeedLeaderElection implements the LeaderElectionRunnable interface, which indicates
	// the metrics server doesn't need leader election.
	NeedLeaderElection() bool

	// Start runs the server.
	// It will install the metrics related resources depending on the server configuration.
	Start(ctx context.Context) error
}

// Options are all available options for the metrics.Server
type Options struct {
	// SecureServing enables serving metrics via https.
	// Per default metrics will be served via http.
	SecureServing bool

	// BindAddress is the bind address for the metrics server.
	// It will be defaulted to ":8080" if unspecified.
	// Set this to "0" to disable the metrics server.
	BindAddress string

	// ExtraHandlers contains a map of handlers (by path) which will be added to the metrics server.
	// This might be useful to register diagnostic endpoints e.g. pprof.
	// Note that pprof endpoints are meant to be sensitive and shouldn't be exposed publicly.
	// If the simple path -> handler mapping offered here is not enough, a new http
	// server/listener should be added as Runnable to the manager via the Add method.
	ExtraHandlers map[string]http.Handler

	// FilterProvider provides a filter which is a func that is added around
	// the metrics and the extra handlers on the metrics server.
	// This can be e.g. used to enforce authentication and authorization on the handlers
	// endpoint by setting this field to filters.WithAuthenticationAndAuthorization.
	FilterProvider func(c *rest.Config, httpClient *http.Client) (Filter, error)

	// CertDir is the directory that contains the server key and certificate. Defaults to
	// <temp-dir>/k8s-metrics-server/serving-certs.
	//
	// Note: This option is only used when TLSOpts does not set GetCertificate.
	// Note: If certificate or key doesn't exist a self-signed certificate will be used.
	CertDir string

	// CertName is the server certificate name. Defaults to tls.crt.
	//
	// Note: This option is only used when TLSOpts does not set GetCertificate.
	// Note: If certificate or key doesn't exist a self-signed certificate will be used.
	CertName string

	// KeyName is the server key name. Defaults to tls.key.
	//
	// Note: This option is only used when TLSOpts does not set GetCertificate.
	// Note: If certificate or key doesn't exist a self-signed certificate will be used.
	KeyName string

	// TLSOpts is used to allow configuring the TLS config used for the server.
	// This also allows providing a certificate via GetCertificate.
	TLSOpts []func(*tls.Config)

	// ListenConfig contains options for listening to an address on the metric server.
	ListenConfig net.ListenConfig
}

// Filter is a func that is added around metrics and extra handlers on the metrics server.
type Filter func(log logr.Logger, handler http.Handler) (http.Handler, error)

// NewServer constructs a new metrics.Server from the provided options.
func NewServer(o Options, config *rest.Config, httpClient *http.Client) (Server, error) {
	o.setDefaults()

	// Skip server creation if metrics are disabled.
	if o.BindAddress == "0" {
		return nil, nil
	}

	// Validate that ExtraHandlers is not overwriting the default /metrics endpoint.
	if o.ExtraHandlers != nil {
		if _, ok := o.ExtraHandlers[defaultMetricsEndpoint]; ok {
			return nil, fmt.Errorf("overriding builtin %s endpoint is not allowed", defaultMetricsEndpoint)
		}
	}

	// Create the metrics filter if a FilterProvider is set.
	var metricsFilter Filter
	if o.FilterProvider != nil {
		var err error
		metricsFilter, err = o.FilterProvider(config, httpClient)
		if err != nil {
			return nil, fmt.Errorf("filter provider failed to create filter for the metrics server: %w", err)
		}
	}

	return &defaultServer{
		metricsFilter: metricsFilter,
		options:       o,
	}, nil
}

// defaultServer is the default implementation used for Server.
type defaultServer struct {
	options Options

	// metricsFilter is a filter which is added around
	// the metrics and the extra handlers on the metrics server.
	metricsFilter Filter

	// mu protects access to the bindAddr field.
	mu sync.RWMutex

	// bindAddr is used to store the bindAddr after the listener has been created.
	// This is used during testing to figure out the port that has been chosen randomly.
	bindAddr string
}

// setDefaults does defaulting for the Server.
func (o *Options) setDefaults() {
	if o.BindAddress == "" {
		o.BindAddress = DefaultBindAddress
	}

	if len(o.CertDir) == 0 {
		o.CertDir = filepath.Join(os.TempDir(), "k8s-metrics-server", "serving-certs")
	}

	if len(o.CertName) == 0 {
		o.CertName = "tls.crt"
	}

	if len(o.KeyName) == 0 {
		o.KeyName = "tls.key"
	}
}

// NeedLeaderElection implements the LeaderElectionRunnable interface, which indicates
// the metrics server doesn't need leader election.
func (*defaultServer) NeedLeaderElection() bool {
	return false
}

// Start runs the server.
// It will install the metrics related resources depend on the server configuration.
func (s *defaultServer) Start(ctx context.Context) error {
	log.Info("Starting metrics server")

	listener, err := s.createListener(ctx, log)
	if err != nil {
		return fmt.Errorf("failed to start metrics server: failed to create listener: %w", err)
	}
	// Storing bindAddr here so we can retrieve it during testing via GetBindAddr.
	s.mu.Lock()
	s.bindAddr = listener.Addr().String()
	s.mu.Unlock()

	mux := http.NewServeMux()

	handler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
	if s.metricsFilter != nil {
		log := log.WithValues("path", defaultMetricsEndpoint)
		var err error
		handler, err = s.metricsFilter(log, handler)
		if err != nil {
			return fmt.Errorf("failed to start metrics server: failed to add metrics filter: %w", err)
		}
	}
	// TODO(JoelSpeed): Use existing Kubernetes machinery for serving metrics
	mux.Handle(defaultMetricsEndpoint, handler)

	for path, extraHandler := range s.options.ExtraHandlers {
		if s.metricsFilter != nil {
			log := log.WithValues("path", path)
			var err error
			extraHandler, err = s.metricsFilter(log, extraHandler)
			if err != nil {
				return fmt.Errorf("failed to start metrics server: failed to add metrics filter to extra handler for path %s: %w", path, err)
			}
		}
		mux.Handle(path, extraHandler)
	}

	log.Info("Serving metrics server", "bindAddress", s.options.BindAddress, "secure", s.options.SecureServing)

	srv := httpserver.New(mux)

	idleConnsClosed := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Info("Shutting down metrics server with timeout of 1 minute")

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			// Error from closing listeners, or context timeout
			log.Error(err, "error shutting down the HTTP server")
		}
		close(idleConnsClosed)
	}()

	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}

	<-idleConnsClosed
	return nil
}

func (s *defaultServer) createListener(ctx context.Context, log logr.Logger) (net.Listener, error) {
	if !s.options.SecureServing {
		return s.options.ListenConfig.Listen(ctx, "tcp", s.options.BindAddress)
	}

	cfg := &tls.Config{ //nolint:gosec
		NextProtos: []string{"h2"},
	}
	// fallback TLS config ready, will now mutate if passer wants full control over it
	for _, op := range s.options.TLSOpts {
		op(cfg)
	}

	if cfg.GetCertificate == nil {
		certPath := filepath.Join(s.options.CertDir, s.options.CertName)
		keyPath := filepath.Join(s.options.CertDir, s.options.KeyName)

		_, certErr := os.Stat(certPath)
		certExists := !os.IsNotExist(certErr)
		_, keyErr := os.Stat(keyPath)
		keyExists := !os.IsNotExist(keyErr)
		if certExists && keyExists {
			// Create the certificate watcher and
			// set the config's GetCertificate on the TLSConfig
			certWatcher, err := certwatcher.New(certPath, keyPath)
			if err != nil {
				return nil, err
			}
			cfg.GetCertificate = certWatcher.GetCertificate

			go func() {
				if err := certWatcher.Start(ctx); err != nil {
					log.Error(err, "certificate watcher error")
				}
			}()
		}
	}

	// If cfg.GetCertificate is still nil, i.e. we didn't configure a cert watcher, fallback to a self-signed certificate.
	if cfg.GetCertificate == nil {
		// Note: Using self-signed certificates here should be good enough. It's just important that we
		// encrypt the communication. For example kube-controller-manager also uses a self-signed certificate
		// for the metrics endpoint per default.
		cert, key, err := certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", []net.IP{{127, 0, 0, 1}}, nil, "")
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate for metrics server: %w", err)
		}

		keyPair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("failed to create self-signed key pair for metrics server: %w", err)
		}
		cfg.Certificates = []tls.Certificate{keyPair}
	}

	l, err := s.options.ListenConfig.Listen(ctx, "tcp", s.options.BindAddress)
	if err != nil {
		return nil, err
	}

	return tls.NewListener(l, cfg), nil
}

func (s *defaultServer) GetBindAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bindAddr
}
