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
	"sync/atomic"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

var (
	statusWarnWaitCertsAvail = "Waiting for TLS certificates to become available"
	statusErrWaitCertsAvail  = "Failed waiting for TLS certificates to become available"
	statusErrServe           = "Failed serving HTTP metrics"
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

	statusWarn atomic.Pointer[string]
	statusErr  atomic.Pointer[string]
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
			s.statusWarn.Store(&statusWarnWaitCertsAvail)
			tlsConfig, err := s.tlsConfigPromise.Await(s.tlsCtx)
			if err != nil {
				s.logger.Error(statusErrWaitCertsAvail, logfields.Error, err)
				errMsg := statusErrWaitCertsAvail + ": " + err.Error()
				s.statusErr.Store(&errMsg)
				return
			}
			s.statusWarn.Store(nil)
			s.server.TLSConfig = tlsConfig.ServerConfig(&tls.Config{ //nolint:gosec
				MinVersion: serveroption.MinTLSVersion,
			})
			listenAndServeFn = func() error {
				return s.server.ListenAndServeTLS("", "")
			}
		}

		err := listenAndServeFn()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error(statusErrServe, logfields.Error, err)
			errMsg := statusErrServe + ": " + err.Error()
			s.statusErr.Store(&errMsg)
		}
	}()

	return nil
}

// Stop implements cell.HookInterface.
func (s *metricsServer) Stop(ctx cell.HookContext) error {
	s.tlsCancel()
	err := s.server.Shutdown(ctx)
	if err != nil {
		s.logger.Error("Failed shutdown of Hubble metrics server", logfields.Error, err)
	}
	s.wg.Wait()
	return err
}

// Status implements Server.
func (m *metricsServer) Status() *models.HubbleMetricsStatus {
	statusErr := m.statusErr.Load()
	if statusErr != nil {
		return &models.HubbleMetricsStatus{
			Msg:   *statusErr,
			State: models.HubbleMetricsStatusStateFailure,
		}
	}

	statusWarn := m.statusWarn.Load()
	if statusWarn != nil {
		return &models.HubbleMetricsStatus{
			Msg:   *statusWarn,
			State: models.HubbleMetricsStatusStateWarning,
		}
	}

	return &models.HubbleMetricsStatus{
		State: models.HubbleMetricsStatusStateOk,
	}
}
