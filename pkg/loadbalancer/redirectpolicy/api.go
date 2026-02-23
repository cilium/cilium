// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server/restapi/service"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type getLrpHandler struct {
	db       *statedb.DB
	lrps     statedb.Table[*LocalRedirectPolicy]
	backends statedb.Table[*lb.Backend]
	pods     statedb.Table[daemonk8s.LocalPod]
}

func (h *getLrpHandler) Handle(params service.GetLrpParams) middleware.Responder {
	return service.NewGetLrpOK().WithPayload(getLRPs(h.db.ReadTxn(), h.lrps, h.backends, h.pods))
}

func getLRPs(txn statedb.ReadTxn, lrps statedb.Table[*LocalRedirectPolicy], backends statedb.Table[*lb.Backend], pods statedb.Table[daemonk8s.LocalPod]) []*models.LRPSpec {
	list := make([]*models.LRPSpec, 0, lrps.NumObjects(txn))
	for lrp := range lrps.All(txn) {
		list = append(list, lrp.getModel(txn, backends, pods))
	}
	return list
}

func (lrp *LocalRedirectPolicy) getModel(txn statedb.ReadTxn, backends statedb.Table[*lb.Backend], pods statedb.Table[daemonk8s.LocalPod]) *models.LRPSpec {
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

	// Get the pseudo-service name for this LRP
	lrpSvcName := lrp.RedirectServiceName()

	// Find all backends for the pseudo-service and build the API models for them.
	beModels := []*models.LRPBackend{}
	for be := range backends.List(txn, lb.BackendByServiceName(lrpSvcName)) {
		ipStr := be.Address.Addr().String()

		// Find the pod that owns this backend IP.
		podID := "unknown"
		for pod := range pods.All(txn) {
			for _, podIP := range pod.Status.PodIPs {
				if podIP.IP == ipStr {
					podID = pod.Namespace + "/" + pod.Name
					goto foundPod
				}
			}
		}
	foundPod:
		// Create the BackendAddress, which contains the IP.
		beAddrModel := &models.BackendAddress{
			IP:       &ipStr,
			Port:     be.Address.Port(),
			Protocol: be.Address.Protocol(),
		}
		if params := be.GetInstance(lrpSvcName); params != nil {
			state, _ := params.State.String()
			beAddrModel.State = state
		}

		// Create the LRPBackend model.
		beModel := &models.LRPBackend{
			PodID:          podID,
			BackendAddress: beAddrModel,
		}
		beModels = append(beModels, beModel)
	}
	feMappingModelArray := make([]*models.FrontendMapping, 0, len(lrp.FrontendMappings))
	for _, feM := range lrp.FrontendMappings {
		feMappingModel := feM.getModel()
		// Attach the resolved backends to the frontend mapping
		feMappingModel.Backends = beModels
		feMappingModelArray = append(feMappingModelArray, feMappingModel)
	}

	return &models.LRPSpec{
		UID:              string(lrp.UID),
		Name:             lrp.ID.Name(),
		Namespace:        lrp.ID.Namespace(),
		FrontendType:     feType,
		LrpType:          lrpType,
		ServiceID:        lrp.ServiceID.String(),
		FrontendMappings: feMappingModelArray,
	}
}

func (feM *feMapping) getModel() *models.FrontendMapping {
	return &models.FrontendMapping{
		FrontendAddress: &models.FrontendAddress{
			IP:       feM.feAddr.AddrCluster().String(),
			Protocol: feM.feAddr.Protocol(),
			Port:     feM.feAddr.Port(),
		},
	}
}
