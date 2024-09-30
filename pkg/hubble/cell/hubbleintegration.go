// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/api/v1/models"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/option"
)

// Hubble is responsible for configuration, initialization, and shutdown of
// every Hubble components including the Hubble observer servers (TCP, UNIX
// domain socket), the Hubble metrics server, etc.
type Hubble struct {
	agentConfig *option.DaemonConfig
	// Observer will be set by the Cilium daemon once the Hubble Observer has
	// been started.
	Observer atomic.Pointer[observer.LocalObserverServer]
}

// new creates and return a new Hubble.
func new(
	agentConfig *option.DaemonConfig,
) *Hubble {
	return &Hubble{
		agentConfig: agentConfig,
		Observer:    atomic.Pointer[observer.LocalObserverServer]{},
	}
}

// Status report the Hubble status for the Cilium Daemon status collector
// probe.
func (h *Hubble) Status(ctx context.Context) *models.HubbleStatus {
	if !h.agentConfig.EnableHubble {
		return &models.HubbleStatus{State: models.HubbleStatusStateDisabled}
	}

	obs := h.Observer.Load()
	if obs == nil {
		return &models.HubbleStatus{
			State: models.HubbleStatusStateWarning,
			Msg:   "Server not initialized",
		}
	}

	req := &observerpb.ServerStatusRequest{}
	status, err := obs.ServerStatus(ctx, req)
	if err != nil {
		return &models.HubbleStatus{State: models.HubbleStatusStateFailure, Msg: err.Error()}
	}

	metricsState := models.HubbleStatusMetricsStateDisabled
	if option.Config.HubbleMetricsServer != "" {
		// TODO: The metrics package should be refactored to be able report its actual state
		metricsState = models.HubbleStatusMetricsStateOk
	}

	hubbleStatus := &models.HubbleStatus{
		State: models.StatusStateOk,
		Observer: &models.HubbleStatusObserver{
			CurrentFlows: int64(status.NumFlows),
			MaxFlows:     int64(status.MaxFlows),
			SeenFlows:    int64(status.SeenFlows),
			Uptime:       strfmt.Duration(time.Duration(status.UptimeNs)),
		},
		Metrics: &models.HubbleStatusMetrics{
			State: metricsState,
		},
	}

	return hubbleStatus
}
