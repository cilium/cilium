// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metricscell

import "github.com/cilium/cilium/api/v1/models"

type HealthReporter interface {
	Status() *models.HubbleMetricsStatus
}

type healthReporter struct {
	server *metricsServer
}

// Status returns the status of the Hubble metrics subsystem.
func (r *healthReporter) Status() (status *models.HubbleMetricsStatus) {
	state := models.HubbleMetricsStatusStateDisabled
	if r.server != nil {
		state = models.HubbleMetricsStatusStateOk
	}

	status = &models.HubbleMetricsStatus{
		State: state,
	}

	return
}
