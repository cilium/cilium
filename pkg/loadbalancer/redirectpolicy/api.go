// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
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
	bes lb.BackendsSeq2,
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
	bes lb.BackendsSeq2,
	feM feMapping,
	matchPortNames bool,
) lb.BackendsSeq2 {
	backendMatchesFrontendMapping := func(be *lb.Backend) bool {
		if !be.Address.Compatible(feM.feAddr) {
			return false
		}
		if matchPortNames && feM.fePort != "" && len(be.PortNames) > 0 {
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
		preferredBackends := lb.BackendsSeq2(lb.PreferredBackendsByAddress(bes))

		numFrontendMapping := len(lrp.FrontendMappings)
		matchNamedPorts := numFrontendMapping > 1

		feMappingModelArray := make([]*models.FrontendMapping, 0, numFrontendMapping)
		for _, feM := range lrp.FrontendMappings {
			feMappingModel := feM.getModel()
			filteredBackends := filterBackendsByFrontendMapping(preferredBackends, feM, matchNamedPorts)
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
		numFrontendMapping := len(lrp.FrontendMappings)

		// In the case of a single-port serviceMatcher, it's possible the LRP controller
		// has created a pseudo-frontend, where the serviceMatcher.toPort[] does not
		// correlate to the actual service port. So, we map in frontends that are
		// associated to the pseudo-service.
		for fe := range frontends.List(txn, lb.FrontendByServiceName(lrpServiceName)) {
			if fe.Type != lb.SVCTypeLocalRedirect {
				continue
			}

			beModels := getBackendModels(podIDByIP, fe.Backends)
			appendFrontendMapping(fe, beModels)
		}

		// Search for any redirected frontends
		for fe := range frontends.List(txn, lb.FrontendByServiceName(lrp.ServiceID)) {
			if fe.Type != lb.SVCTypeClusterIP {
				continue
			}

			// Scenario 1, this frontend is redirected. It must be mapped to this LRP
			// to be displayed.
			if fe.RedirectTo != nil {
				if !fe.RedirectTo.Equal(lrpServiceName) {
					continue
				}

				beModels := getBackendModels(podIDByIP, fe.Backends)
				appendFrontendMapping(fe, beModels)
				continue
			}

			// Scenario 2, this frontend is not redirected, but whether it's candidate
			// to be shown depends on the FrontendType.
			switch lrp.FrontendType {
			case svcFrontendAll:
				// On an all-port serviceMatcher, if the service had been properly
				// redirected then it would be included in scenario 1 above. Instead,
				// we show this with FE with no backends so it's clear the frontend is
				// at least matching the LRP criteria, but with little effect.
				beModels := []*models.LRPBackend{}
				appendFrontendMapping(fe, beModels)

			case svcFrontendSinglePort:
				// On a single-port serviceMatcher, we include this frontend if its
				// address matches the first frontend mapping exactly.
				if numFrontendMapping == 0 {
					continue
				}

				lrpAddr := lrp.FrontendMappings[0].feAddr
				if lrpAddr.Compatible(fe.Address) && lrpAddr.Port() == fe.Address.Port() {
					beModels := getBackendModels(podIDByIP, fe.Backends)
					appendFrontendMapping(fe, beModels)
				}

			case svcFrontendNamedPorts:
				// On a named port serviceMatcher, for mapping to be successful the names
				// must match between redirectBackend.toPorts, pod spec and service ports.
				// In that case, if this FE matched, it would have been redirected and thus
				// included via scenario 1 above. If it did not, then either (a) this FE
				// was not part of the FrontendMapping, or (b) there's no backends
				// available. In the case of (b), we should still display this FE, so it's
				// clear it matches the LRP criteria, but with little effect.
				hasMapping := slices.ContainsFunc(lrp.FrontendMappings, func(feM feMapping) bool {
					return feM.feAddr.Compatible(fe.Address) && feM.feAddr.Port() == fe.Address.Port()
				})
				if hasMapping {
					beModels := []*models.LRPBackend{}
					appendFrontendMapping(fe, beModels)
				}
			}
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
