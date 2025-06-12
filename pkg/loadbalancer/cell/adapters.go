// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	serviceapi "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// The adapters in this file replaces the [service.ServiceManager]
// implementation.  These are meant to be temporary until the uses of these
// interfaces have been migrated over to using the tables directly.

type adapterParams struct {
	cell.In

	Clientset    client.Clientset
	JobGroup     job.Group
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	Config       loadbalancer.Config
	DB           *statedb.DB
	Services     statedb.Table[*loadbalancer.Service]
	Backends     statedb.Table[*loadbalancer.Backend]
	Frontends    statedb.Table[*loadbalancer.Frontend]
	Ops          *lbreconciler.BPFOps
	Writer       *writer.Writer
	TestConfig   *loadbalancer.TestConfig `optional:"true"`
}

// newAdapters constructs the ServiceCache and ServiceManager adapters
func newAdapters(p adapterParams) service.ServiceManager {
	sma := &serviceManagerAdapter{
		log:          p.Log,
		daemonConfig: p.DaemonConfig,
		db:           p.DB,
		services:     p.Services,
		frontends:    p.Frontends,
		writer:       p.Writer,
	}
	return sma
}

type serviceManagerAdapter struct {
	log          *slog.Logger
	daemonConfig *option.DaemonConfig
	db           *statedb.DB
	services     statedb.Table[*loadbalancer.Service]
	frontends    statedb.Table[*loadbalancer.Frontend]
	writer       *writer.Writer
}

// GetCurrentTs implements service.ServiceManager.
func (s *serviceManagerAdapter) GetCurrentTs() time.Time {
	// Used by kubeproxyhealthz.
	return time.Now()
}

// GetDeepCopyServices implements service.ServiceManager.
func (s *serviceManagerAdapter) GetDeepCopyServices() (svcs []*loadbalancer.LegacySVC) {
	// Used by REST API.
	txn := s.db.ReadTxn()
	for fe := range s.frontends.All(txn) {
		bes := []*loadbalancer.LegacyBackend{}
		svc := fe.Service
		for be := range fe.Backends {
			// Get the instance of the referenced service. This may be different from fe.ServiceName
			// if it is being redirected.
			beModel := &loadbalancer.LegacyBackend{
				FEPortName: "",
				ID:         0,
				Weight:     be.Weight,
				NodeName:   be.NodeName,
				ZoneID:     s.daemonConfig.GetZoneID(be.Zone),
				L3n4Addr:   be.Address,
				State:      be.State,
				Preferred:  true,
			}
			if len(be.PortNames) == 0 {
				bes = append(bes, beModel)
			} else {
				for _, portName := range be.PortNames {
					beModel = beModel.DeepCopy()
					beModel.FEPortName = portName
					bes = append(bes, beModel)
				}
			}
		}
		proxyPort := uint16(0)
		if svc.ProxyRedirect != nil {
			proxyPort = svc.ProxyRedirect.ProxyPort
		}

		svcType := fe.Type
		if fe.RedirectTo != nil {
			svcType = loadbalancer.SVCTypeLocalRedirect
		}

		svcModel := &loadbalancer.LegacySVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: fe.Address,
				ID:       loadbalancer.ID(fe.ID),
			},
			Type:        svcType,
			Name:        fe.ServiceName,
			Annotations: fe.Service.Annotations,
			Backends:    bes,

			ForwardingMode:            "", // FIXME (not implemented)
			ExtTrafficPolicy:          svc.ExtTrafficPolicy,
			IntTrafficPolicy:          svc.IntTrafficPolicy,
			NatPolicy:                 svc.NatPolicy,
			SourceRangesPolicy:        "",                                  // FIXME (not implemented)
			ProxyDelegation:           loadbalancer.SVCProxyDelegationNone, // FIXME (not implemented)
			SessionAffinity:           svc.SessionAffinity,
			SessionAffinityTimeoutSec: uint32(svc.SessionAffinityTimeout),
			HealthCheckNodePort:       svc.HealthCheckNodePort,
			LoadBalancerAlgorithm:     svc.GetLBAlgorithmAnnotation(),
			LoadBalancerSourceRanges:  nil, // FIXME CIDR vs *CIDR
			L7LBProxyPort:             proxyPort,
			LoopbackHostport:          svc.LoopbackHostPort,
		}
		svcs = append(svcs, svcModel)
	}
	return
}

// GetLastUpdatedTs implements service.ServiceManager.
func (s *serviceManagerAdapter) GetLastUpdatedTs() time.Time {
	// Used by kubeproxyhealthz. Unclear how important it is to have real last updated time here.
	// We could e.g. keep a timestamp behind an atomic in BPFOps to implement that.
	return time.Now()
}

// GetServiceIDs implements service.ServiceReader.
func (s *serviceManagerAdapter) GetServiceIDs() []loadbalancer.ServiceID {
	// Used by pkg/act.

	txn := s.db.ReadTxn()
	ids := make([]loadbalancer.ServiceID, 0, s.frontends.NumObjects(txn))
	for fe := range s.frontends.All(txn) {
		if fe.Status.Kind == reconciler.StatusKindDone {
			ids = append(ids, fe.ID)
		}
	}
	return ids
}

// GetServiceNameByAddr implements service.ServiceReader.
func (s *serviceManagerAdapter) GetServiceNameByAddr(addr loadbalancer.L3n4Addr) (string, string, bool) {
	// Used by hubble.

	txn := s.db.ReadTxn()

	fe, _, found := s.frontends.Get(txn, loadbalancer.FrontendByAddress(addr))
	if !found {
		return "", "", false
	}
	return fe.Service.Name.Namespace, fe.Service.Name.Name, true
}

var _ service.ServiceManager = &serviceManagerAdapter{}

type serviceRestApiHandlerParams struct {
	cell.In

	Logger         *slog.Logger
	ServiceManager service.ServiceManager
}

type serviceRestApiHandlerOut struct {
	cell.Out

	GetServiceIDHandler serviceapi.GetServiceIDHandler
	GetServiceHandler   serviceapi.GetServiceHandler
}

func newServiceRestApiHandler(params serviceRestApiHandlerParams) serviceRestApiHandlerOut {
	return serviceRestApiHandlerOut{
		GetServiceIDHandler: &getServiceIDHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
		GetServiceHandler: &getServiceHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
	}
}

type getServiceIDHandler struct {
	logger         *slog.Logger
	serviceManager service.ServiceManager
}

func (h *getServiceIDHandler) Handle(params serviceapi.GetServiceIDParams) middleware.Responder {
	// Lookups by ID not supported.
	return serviceapi.NewGetServiceIDNotFound()
}

type getServiceHandler struct {
	logger         *slog.Logger
	serviceManager service.ServiceManager
}

func (h *getServiceHandler) Handle(params serviceapi.GetServiceParams) middleware.Responder {
	h.logger.Debug(
		"GET /service request",
		logfields.Params, params,
	)
	list := GetServiceModelList(h.serviceManager)
	return serviceapi.NewGetServiceOK().WithPayload(list)
}

func GetServiceModelList(svc service.ServiceManager) []*models.Service {
	svcs := svc.GetDeepCopyServices()
	list := make([]*models.Service, 0, len(svcs))
	for _, v := range svcs {
		list = append(list, v.GetModel())
	}
	return list
}
