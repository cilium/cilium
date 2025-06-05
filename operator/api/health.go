// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"
	"k8s.io/client-go/discovery"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/operator/server/restapi/operator"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type isOperatorLeadingFunc func() bool

func HealthHandlerCell(
	isOperatorLeading isOperatorLeadingFunc,
) cell.Cell {
	return cell.Module(
		"health-handler",
		"Operator health HTTP handler",

		cell.Provide(func(
			clientset k8sClient.Clientset,
			kvstoreClient kvstore.Client,
			logger *slog.Logger,
		) operator.GetHealthzHandler {
			if !clientset.IsEnabled() {
				return &healthHandler{
					enabled: false,
				}
			}

			return &healthHandler{
				enabled:           true,
				isOperatorLeading: isOperatorLeading,
				kvstoreClient:     kvstoreClient,
				discovery:         clientset.Discovery(),
				log:               logger,
			}
		}),
	)
}

type healthHandler struct {
	enabled           bool
	isOperatorLeading isOperatorLeadingFunc
	kvstoreClient     kvstore.Client
	discovery         discovery.DiscoveryInterface
	log               *slog.Logger
	consecutiveErrors atomic.Uint64
}

func (h *healthHandler) Handle(params operator.GetHealthzParams) middleware.Responder {
	if !h.enabled {
		return operator.NewGetHealthzNotImplemented()
	}

	if err := h.checkStatus(); err != nil {
		if h.consecutiveErrors.Add(1) <= 3 {
			h.log.Info("Health check failed", logfields.Error, err)
		} else {
			h.log.Warn("Health check failed", logfields.Error, err)
		}

		return operator.NewGetHealthzInternalServerError().WithPayload(err.Error())
	}

	if h.consecutiveErrors.Swap(0) > 0 {
		h.log.Info("Health check succeeded after failures")
	}

	return operator.NewGetHealthzOK().WithPayload("ok")
}

// checkStatus verifies the connection status to the kvstore and the
// k8s apiserver and returns an error if any of them is unhealthy
func (h *healthHandler) checkStatus() error {
	if h.kvstoreClient.IsEnabled() {
		status := h.kvstoreClient.Status()
		if status.State != models.StatusStateOk {
			return errors.New(status.Msg)
		}
	}
	_, err := h.discovery.ServerVersion()
	return err
}
