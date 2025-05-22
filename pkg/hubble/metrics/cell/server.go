// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	server           *http.Server
	tlsConfigPromise tlsConfigPromise

	statusWarn atomic.Pointer[string]
	statusErr  atomic.Pointer[string]
}

func newMetricsServer(p params) Server {
	if p.Config.MetricsServer == "" {
		p.Logger.Info("The Hubble metrics server is disabled")
		return nil
	}

	mux := metrics.ServerHandler(metrics.Registry, p.Config.EnableOpenMetrics)
	server := &metricsServer{
		logger: p.Logger,
		server: &http.Server{
			Addr:    p.Config.MetricsServer,
			Handler: mux,
		},
		tlsConfigPromise: p.TLSConfigPromise,
	}

	p.JobGroup.Add(job.OneShot("hubble-metrics-server", func(ctx context.Context, _ cell.Health) error {
		return server.Run(ctx)
	}))
	p.Lifecycle.Append(cell.Hook{
		OnStop: func(ctx cell.HookContext) error {
			err := server.server.Shutdown(ctx)
			if err != nil {
				server.logger.Error("Shutdown Hubble metrics server failed", logfields.Error, err)
			}
			return err
		},
	})
	return server
}

func (s *metricsServer) Run(ctx context.Context) error {
	tlsEnabled := s.tlsConfigPromise != nil
	s.logger.Info("Starting Hubble metrics server",
		logfields.Address, s.server.Addr,
		logfields.TLS, tlsEnabled,
	)

	listenAndServeFn := s.server.ListenAndServe
	if tlsEnabled {
		s.logger.Info(statusWarnWaitCertsAvail)
		s.statusWarn.Store(&statusWarnWaitCertsAvail)
		tlsConfig, err := s.tlsConfigPromise.Await(ctx)
		if err != nil {
			errMsg := statusErrWaitCertsAvail + ": " + err.Error()
			s.statusErr.Store(&errMsg)
			return fmt.Errorf("failed waiting for TLS config to resolve: %w", err)
		}
		s.statusWarn.Store(nil)
		s.server.TLSConfig = tlsConfig.ServerConfig(&tls.Config{ //nolint:gosec
			MinVersion: serveroption.MinTLSVersion,
		})
		listenAndServeFn = func() error {
			return s.server.ListenAndServeTLS("", "")
		}
	}

	if err := listenAndServeFn(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errMsg := statusErrServe + ": " + err.Error()
		s.statusErr.Store(&errMsg)
		return fmt.Errorf("unable to listen and serve Hubble metrics server: %w", err)
	}
	return nil
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
