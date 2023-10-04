// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"time"

	"github.com/go-openapi/runtime/middleware"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// moduleExcludes tracks modules that should be excluded from the health report.
var moduleExcludes = map[string]struct{}{
	// daemon currently does not rollup status and hence reports default health aka unknown.
	"daemon": {},
}

type getHealth struct {
	daemon *Daemon
}

// NewGetHealthHandler returns a new instance.
func NewGetHealthHandler(d *Daemon) GetHealthHandler {
	return &getHealth{daemon: d}
}

// Handle receives agent health request and returns modules health report.
func (h *getHealth) Handle(params GetHealthParams) middleware.Responder {
	sr := h.daemon.getHealthReport()
	return NewGetHealthOK().WithPayload(&sr)
}

func (d *Daemon) getHealthReport() models.ModulesHealth {
	mm := d.healthProvider.All()
	rr := make([]*models.ModuleHealth, 0, len(mm))
	for _, m := range mm {
		if _, ok := moduleExcludes[m.ModuleID]; ok {
			continue
		}
		rr = append(rr, toModuleHealth(m))
	}

	return models.ModulesHealth{Modules: rr}
}

// Helpers...

func toModuleHealth(m cell.Status) *models.ModuleHealth {
	return &models.ModuleHealth{
		ModuleID:    m.ModuleID,
		Message:     m.Message,
		Level:       string(m.Level),
		LastOk:      toAgeHuman(m.LastOK),
		LastUpdated: toAgeHuman(m.LastUpdated),
	}
}

func toAgeHuman(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}

	return duration.HumanDuration(time.Since(t))
}
