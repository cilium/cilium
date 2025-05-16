// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

type metricsServer struct {
	logger *slog.Logger

	server http.Server

	tlsConfigPromise promise.Promise[*certloader.WatchedServerConfig]
}

func newMetricsServer(p params) *metricsServer {
	handler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{
		EnableOpenMetrics: p.Config.EnableOpenMetrics,
	})
	handler = promhttp.InstrumentHandlerCounter(metrics.RequestsTotal, handler)
	handler = promhttp.InstrumentHandlerDuration(metrics.RequestDuration, handler)

	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)

	server := &metricsServer{
		logger: p.Logger,
		server: http.Server{
			Addr:    p.Config.MetricsServer,
			Handler: mux,
		},
		tlsConfigPromise: p.TLSConfigPromise,
	}
	return server
}

// Start implements cell.HookInterface.
// TODO: resolve promise to signal to hubble cell that server is started.
func (s *metricsServer) Start(ctx cell.HookContext) error {
	go func() {
		tlsEnabled := s.tlsConfigPromise != nil
		s.logger.Info("Starting Hubble metrics server",
			logfields.Address, s.server.Addr,
			logfields.TLS, tlsEnabled,
		)

		listenAndServeFn := s.server.ListenAndServe
		if tlsEnabled {
			tlsConfig, err := s.tlsConfigPromise.Await(ctx)
			if err != nil {
				s.logger.Error("Unable to retrieve TLS config for Hubble metrics server", logfields.Error, err)
				return
			}
			s.server.TLSConfig = tlsConfig.ServerConfig(&tls.Config{ //nolint:gosec
				MinVersion: serveroption.MinTLSVersion,
			})
			listenAndServeFn = func() error {
				return s.server.ListenAndServeTLS("", "")
			}
		}

		err := listenAndServeFn()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("Unable to start Hubble metrics server", logfields.Error, err)
		}
	}()

	return nil
}

// Stop implements cell.HookInterface.
func (s *metricsServer) Stop(ctx cell.HookContext) error {
	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Error("Shutdown Hubble metrics server failed", logfields.Error, err)
		return err
	}
	return nil
}
