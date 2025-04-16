// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server/restapi/service"
)

type getLrpHandler struct {
	db   *statedb.DB
	lrps statedb.Table[*LocalRedirectPolicy]
}

func (h *getLrpHandler) Handle(params service.GetLrpParams) middleware.Responder {
	return service.NewGetLrpOK().WithPayload(getLRPs(h.db.ReadTxn(), h.lrps))
}

func getLRPs(txn statedb.ReadTxn, lrps statedb.Table[*LocalRedirectPolicy]) []*models.LRPSpec {
	list := make([]*models.LRPSpec, 0, lrps.NumObjects(txn))
	for lrp := range lrps.All(txn) {
		list = append(list, lrp.getModel())
	}
	return list
}

func (lrp *LocalRedirectPolicy) getModel() *models.LRPSpec {
	if lrp == nil {
		return nil
	}

	var feType, lrpType string
	switch lrp.FrontendType {
	case frontendTypeUnknown:
		feType = "unknown"
	case svcFrontendAll:
		feType = "clusterIP + all svc ports"
	case svcFrontendNamedPorts:
		feType = "clusterIP + named ports"
	case svcFrontendSinglePort:
		feType = "clusterIP + port"
	case addrFrontendSinglePort:
		feType = "IP + port"
	case addrFrontendNamedPorts:
		feType = "IP + named ports"
	}

	switch lrp.LRPType {
	case lrpConfigTypeNone:
		lrpType = "none"
	case lrpConfigTypeAddr:
		lrpType = "addr"
	case lrpConfigTypeSvc:
		lrpType = "svc"
	}

	feMappingModelArray := make([]*models.FrontendMapping, 0, len(lrp.FrontendMappings))
	for _, feM := range lrp.FrontendMappings {
		feMappingModelArray = append(feMappingModelArray, feM.getModel())
	}

	return &models.LRPSpec{
		UID:              string(lrp.UID),
		Name:             lrp.ID.Name,
		Namespace:        lrp.ID.Namespace,
		FrontendType:     feType,
		LrpType:          lrpType,
		ServiceID:        lrp.ServiceID.String(),
		FrontendMappings: feMappingModelArray,
	}
}

func (feM *feMapping) getModel() *models.FrontendMapping {
	return &models.FrontendMapping{
		FrontendAddress: &models.FrontendAddress{
			IP:       feM.feAddr.AddrCluster.String(),
			Protocol: feM.feAddr.Protocol,
			Port:     feM.feAddr.Port,
		},
	}
}
