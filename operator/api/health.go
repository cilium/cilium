// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/discovery"

	"github.com/cilium/cilium/api/v1/operator/server/restapi/operator"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore"
)

type getHealthz struct {
	*Server
}

// NewGetHealthzHandler handles health requests.
func NewGetHealthzHandler(s *Server) operator.GetHealthzHandler {
	return &getHealthz{Server: s}
}

// Handle handles GET requests for /healthz .
func (h *getHealthz) Handle(params operator.GetHealthzParams) middleware.Responder {
	select {
	// only start serving the real health check once all systems all up and running
	case <-h.Server.allSystemsGo:
		if err := h.Server.checkStatus(); err != nil {
			log.WithError(err).Warn("Health check status")

			return operator.NewGetHealthzInternalServerError().WithPayload(err.Error())
		}
	default:
	}

	return operator.NewGetHealthzOK().WithPayload("ok")
}

type kvstoreEnabledFunc func() bool

func HealthHandlerCell(kvstoreEnabled kvstoreEnabledFunc) cell.Cell {
	return cell.Module(
		"health-handler",
		"Operator health HTTP handler",

		cell.Provide(func(
			clientset k8sClient.Clientset,
			logger logrus.FieldLogger,
			cfg SharedConfig,
		) operator.GetHealthzHandler {
			if !cfg.EnableK8s || !clientset.IsEnabled() {
				return &healthHandler{
					enabled: false,
				}
			}

			return &healthHandler{
				enabled:        true,
				kvstoreEnabled: kvstoreEnabled,
				discovery:      clientset.Discovery(),
				log:            logger,
			}
		}),
	)
}

type healthHandler struct {
	enabled        bool
	discovery      discovery.DiscoveryInterface
	kvstoreEnabled kvstoreEnabledFunc
	log            logrus.FieldLogger
}

func (h *healthHandler) Handle(params operator.GetHealthzParams) middleware.Responder {
	if !h.enabled {
		return operator.NewGetHealthzNotImplemented()
	}

	if err := h.checkStatus(); err != nil {
		h.log.WithError(err).Warn("Health check status")
		return operator.NewGetHealthzInternalServerError().WithPayload(err.Error())
	}

	return operator.NewGetHealthzOK().WithPayload("ok")
}

// checkStatus verifies the connection status to the kvstore and the
// k8s apiserver and returns an error if any of them is unhealthy
func (h *healthHandler) checkStatus() error {
	if h.kvstoreEnabled() {
		client := kvstore.Client()
		if client == nil {
			return errors.New("kvstore client not configured")
		}
		if _, err := client.Status(); err != nil {
			return err
		}
	}
	_, err := h.discovery.ServerVersion()
	return err
}
