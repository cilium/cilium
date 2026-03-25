// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"iter"
	"slices"
	"strings"

	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server/restapi/service"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type getLrpHandler struct {
	db        *statedb.DB
	lrps      statedb.Table[*LocalRedirectPolicy]
	frontends statedb.Table[*lb.Frontend]
	backends  statedb.Table[*lb.Backend]
	pods      statedb.Table[k8sTables.LocalPod]
}

func (h *getLrpHandler) Handle(params service.GetLrpParams) middleware.Responder {
	return service.NewGetLrpOK().WithPayload(getLRPs(h.db.ReadTxn(), h.lrps, h.frontends, h.backends, h.pods))
}

func getLRPs(txn statedb.ReadTxn, lrps statedb.Table[*LocalRedirectPolicy], frontends statedb.Table[*lb.Frontend], backends statedb.Table[*lb.Backend], pods statedb.Table[k8sTables.LocalPod]) []*models.LRPSpec {
	list := make([]*models.LRPSpec, 0, lrps.NumObjects(txn))
	for lrp := range lrps.All(txn) {
		list = append(list, lrp.getModel(txn, frontends, backends, pods))
	}
	return list
}

func (lrp *LocalRedirectPolicy) getModel(txn statedb.ReadTxn, frontends statedb.Table[*lb.Frontend], backends statedb.Table[*lb.Backend], pods statedb.Table[k8sTables.LocalPod]) *models.LRPSpec {
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

	return &models.LRPSpec{
		UID:              string(lrp.UID),
		Name:             lrp.ID.Name(),
		Namespace:        lrp.ID.Namespace(),
		FrontendType:     feType,
		LrpType:          lrpType,
		ServiceID:        lrp.ServiceID.String(),
		FrontendMappings: lrp.getFrontendMappingModels(txn, frontends, backends, pods),
	}
}

// Returns a map of Pod IDs (namespace/pod-name), indexed by Pod IP address.
func getPodIDByIP(txn statedb.ReadTxn, pods statedb.Table[k8sTables.LocalPod]) map[string]string {
	podIDByIP := map[string]string{}
	for pod := range pods.All(txn) {
		podID := pod.Namespace + "/" + pod.Name
		for _, podIP := range pod.Status.PodIPs {
			podIDByIP[podIP.IP] = podID
		}
	}
	return podIDByIP
}

// Returns an array of Backend models, converted from a series of backends from StateDB.
func getBackendModels(
	podIDByIP map[string]string,
	bes iter.Seq2[*lb.Backend, statedb.Revision],
) []*models.LRPBackend {
	beModels := []*models.LRPBackend{}
	if bes == nil {
		return beModels
	}

	appendBackendModel := func(podID string, beAddrStr *string, be *lb.Backend) {
		beAddrModel := &models.BackendAddress{
			IP:       beAddrStr,
			Port:     be.Address.Port(),
			Protocol: be.Address.Protocol(),
		}
		state, _ := be.State.String()
		beAddrModel.State = state

		beModels = append(beModels, &models.LRPBackend{
			PodID:          podID,
			BackendAddress: beAddrModel,
		})
	}

	// Iterate over all backends. For each entry, we append a new backend model,
	// using the backend IP to map into a PodID.
	for be := range bes {
		beAddrStr := be.Address.Addr().String()
		podID, found := podIDByIP[beAddrStr]
		if !found {
			podID = "unknown"
		}
		appendBackendModel(podID, &beAddrStr, be)
	}

	return beModels
}

// filterBackendsByFrontendMapping narrows the backend list of a pseudo-service
// generated from an addressMatcher LRP to a subset of pods that would actually
// be mapped by the controller.
func filterBackendsByFrontendMapping(
	bes iter.Seq2[*lb.Backend, statedb.Revision],
	feM feMapping,
) iter.Seq2[*lb.Backend, statedb.Revision] {
	backendMatchesFrontendMapping := func(be *lb.Backend) bool {
		if be.Address.Protocol() != feM.feAddr.Protocol() {
			return false
		}
		if be.Address.IsIPv6() != feM.feAddr.IsIPv6() {
			return false
		}
		if feM.fePort != "" && len(be.PortNames) > 0 {
			return slices.ContainsFunc(be.PortNames, func(portName string) bool {
				return strings.EqualFold(portName, string(feM.fePort))
			})
		}
		return true
	}

	return func(yield func(*lb.Backend, statedb.Revision) bool) {
		for be, rev := range bes {
			if !backendMatchesFrontendMapping(be) {
				continue
			}
			if !yield(be, rev) {
				return
			}
		}
	}
}

// Returns an array of FrontendMapping models for a LocalRedirectPolicy based on the
// StateDB frontend and backend tables.
func (lrp *LocalRedirectPolicy) getFrontendMappingModels(
	txn statedb.ReadTxn,
	frontends statedb.Table[*lb.Frontend],
	backends statedb.Table[*lb.Backend],
	pods statedb.Table[k8sTables.LocalPod],
) []*models.FrontendMapping {
	podIDByIP := getPodIDByIP(txn, pods)

	switch lrp.LRPType {
	case lrpConfigTypeAddr:
		// For addressMatcher LRPs, the configured frontend mappings are the source of
		// truth for frontend information. Since these mappings do not carry writer-
		// selected backends, filter the pseudo-service backends per mapping to match
		// the frontend/backend association the writer would produce.
		bes, _ := lb.ListBackendsByServiceName(txn, backends, lrp.RedirectServiceName())
		preferredBackends := lb.PreferredBackendsByAddress(bes)
		feMappingModelArray := make([]*models.FrontendMapping, 0, len(lrp.FrontendMappings))
		for _, feM := range lrp.FrontendMappings {
			feMappingModel := feM.getModel()
			filteredBackends := filterBackendsByFrontendMapping(preferredBackends, feM)
			feMappingModel.Backends = getBackendModels(podIDByIP, filteredBackends)
			feMappingModelArray = append(feMappingModelArray, feMappingModel)
		}
		return feMappingModelArray

	case lrpConfigTypeSvc:
		// for serviceMatcher LRPs, the internal frontendMapping has dummy IP address
		// information in, so we don't use it here. Instead, we query StateDB for
		// frontends associated with the matched service. We then build backend models
		// from the backends associated with those frontends.
		feMappingModelArray := []*models.FrontendMapping{}
		appendFrontendMapping := func(fe *lb.Frontend, beModels []*models.LRPBackend) {
			feMappingModelArray = append(feMappingModelArray, &models.FrontendMapping{
				FrontendAddress: &models.FrontendAddress{
					IP:       fe.Address.AddrCluster().String(),
					Protocol: fe.Address.Protocol(),
					Port:     fe.Address.Port(),
				},
				Backends: beModels,
			})
		}

		lrpServiceName := lrp.RedirectServiceName()

		// Search for any redirected frontends
		for fe := range frontends.List(txn, lb.FrontendByServiceName(lrp.ServiceID)) {
			if fe.Type != lb.SVCTypeClusterIP {
				continue
			}
			if fe.RedirectTo == nil || !fe.RedirectTo.Equal(lrpServiceName) {
				continue
			}

			beModels := getBackendModels(podIDByIP, iter.Seq2[*lb.Backend, statedb.Revision](fe.Backends))
			appendFrontendMapping(fe, beModels)
		}

		return feMappingModelArray
	}

	return nil
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
