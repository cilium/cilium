// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

type Server interface {
	Status() *models.HubbleMetricsStatus
}

type metricsServer struct {
	logger *slog.Logger

	server *http.Server

	tlsConfigPromise promise.Promise[*certloader.WatchedServerConfig]

	wg        sync.WaitGroup
	tlsCtx    context.Context
	tlsCancel context.CancelFunc
}

func newMetricsServer(p params) Server {
	if p.Config.MetricsServer == "" {
		p.Logger.Info("The Hubble metrics server is disabled")
		return nil
	}

	mux := metrics.ServerHandler(metrics.Registry, p.Config.EnableOpenMetrics)
	ctx, cancel := context.WithCancel(context.Background())
	server := &metricsServer{
		logger: p.Logger,
		server: &http.Server{
			Addr:    p.Config.MetricsServer,
			Handler: mux,
		},
		tlsConfigPromise: p.TLSConfigPromise,
		tlsCtx:           ctx,
		tlsCancel:        cancel,
	}
	p.Lifecycle.Append(server)
	return server
}

// Start implements cell.HookInterface.
func (s *metricsServer) Start(_ cell.HookContext) error {
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()

		tlsEnabled := s.tlsConfigPromise != nil
		s.logger.Info("Starting Hubble metrics server",
			logfields.Address, s.server.Addr,
			logfields.TLS, tlsEnabled,
		)

		listenAndServeFn := s.server.ListenAndServe
		if tlsEnabled {
			tlsConfig, err := s.tlsConfigPromise.Await(s.tlsCtx)
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
	s.tlsCancel()
	err := s.server.Shutdown(ctx)
	if err != nil {
		s.logger.Error("Shutdown Hubble metrics server failed", logfields.Error, err)
	}
	s.wg.Wait()
	return err
}

// Status implements Server.
func (m *metricsServer) Status() *models.HubbleMetricsStatus {
	return &models.HubbleMetricsStatus{
		State: models.HubbleMetricsStatusStateOk,
	}
}
