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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Server interface {
	Status() *models.HubbleMetricsStatus
}

type metricsServer struct {
	logger *slog.Logger

	server           *http.Server
	tlsConfigPromise tlsConfigPromise
}

func newMetricsServer(p params) Server {
	if p.Config.MetricsServer == "" {
		p.Logger.Info("The Hubble metrics server is disabled")
		return nil
	}

	srv := &http.Server{
		Addr: p.Config.MetricsServer,
	}
	metrics.InitMetricsServerHandler(srv, metrics.Registry, p.Config.EnableOpenMetrics)

	server := &metricsServer{
		logger:           p.Logger,
		server:           srv,
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
		s.logger.Info("Waiting for TLS certificates to become available")
		tlsConfig, err := s.tlsConfigPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed waiting for TLS config to resolve: %w", err)
		}
		s.server.TLSConfig = tlsConfig.ServerConfig(&tls.Config{ //nolint:gosec
			MinVersion: serveroption.MinTLSVersion,
		})
		listenAndServeFn = func() error {
			return s.server.ListenAndServeTLS("", "")
		}
	}

	if err := listenAndServeFn(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("unable to listen and serve Hubble metrics server: %w", err)
	}
	return nil
}

// Status implements Server.
func (m *metricsServer) Status() *models.HubbleMetricsStatus {
	return &models.HubbleMetricsStatus{
		State: models.HubbleMetricsStatusStateOk,
	}
}
