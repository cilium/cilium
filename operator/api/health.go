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

type kvstoreEnabledFunc func() bool
type isOperatorLeadingFunc func() bool

func HealthHandlerCell(
	kvstoreEnabled kvstoreEnabledFunc,
	isOperatorLeading isOperatorLeadingFunc,
) cell.Cell {
	return cell.Module(
		"health-handler",
		"Operator health HTTP handler",

		cell.Provide(func(
			clientset k8sClient.Clientset,
			logger logrus.FieldLogger,
		) operator.GetHealthzHandler {
			if !clientset.IsEnabled() {
				return &healthHandler{
					enabled: false,
				}
			}

			return &healthHandler{
				enabled:           true,
				isOperatorLeading: isOperatorLeading,
				kvstoreEnabled:    kvstoreEnabled,
				discovery:         clientset.Discovery(),
				log:               logger,
			}
		}),
	)
}

type healthHandler struct {
	enabled           bool
	isOperatorLeading isOperatorLeadingFunc
	kvstoreEnabled    kvstoreEnabledFunc
	discovery         discovery.DiscoveryInterface
	log               logrus.FieldLogger
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
	// We check if we are the leader here because only the leader has
	// access to the kvstore client. Otherwise, the kvstore client check
	// will block. It is safe for a non-leader to skip this check, as the
	// it is the leader's responsibility to report the status of the
	// kvstore client.
	if h.isOperatorLeading() && h.kvstoreEnabled() {
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
