// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/redirectpolicy"

	"github.com/go-openapi/runtime/middleware"
)

type getLRP struct {
	rpm *redirectpolicy.Manager
}

func NewGetLrpHandler(rpm *redirectpolicy.Manager) GetLrpHandler {
	return &getLRP{rpm: rpm}
}

func (h *getLRP) Handle(params GetLrpParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /lrp request")
	return NewGetLrpOK().WithPayload(getLRPs(h.rpm))
}

func getLRPs(rpm *redirectpolicy.Manager) []*models.LRPSpec {
	lrps := rpm.GetLRPs()
	list := make([]*models.LRPSpec, 0, len(lrps))
	for _, v := range lrps {
		list = append(list, v.GetModel())
	}
	return list
}
