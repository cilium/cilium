// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type getHealth struct {
	daemon *Daemon
}

// NewGetHealthHandler returns a new instance.
func NewGetHealthHandler(d *Daemon) GetHealthHandler {
	return &getHealth{daemon: d}
}

// Handle receives agent health request and returns modules health report.
func (h *getHealth) Handle(params GetHealthParams) middleware.Responder {
	sr, err := h.daemon.getHealthReport()
	if err != nil {
		return api.Error(http.StatusInternalServerError, err)
	}
	return NewGetHealthOK().WithPayload(&sr)
}

func (d *Daemon) getHealthReport() (models.ModulesHealth, error) {
	mm := d.healthProvider.All()
	rr := make([]*models.ModuleHealth, 0, len(mm))
	for _, m := range mm {
		mh, err := toModuleHealth(m)
		if err != nil {
			return models.ModulesHealth{}, err
		}
		rr = append(rr, mh)
	}

	return models.ModulesHealth{Modules: rr}, nil
}

// Helpers...

func toModuleHealth(m cell.Status) (*models.ModuleHealth, error) {
	d, err := m.JSON()
	if err != nil {
		return nil, err
	}
	return &models.ModuleHealth{
		ModuleID:    m.FullModuleID.String(),
		Message:     string(d),
		Level:       string(m.Level()),
		LastOk:      client.ToAgeHuman(m.LastOK),
		LastUpdated: client.ToAgeHuman(m.LastUpdated),
	}, nil
}
