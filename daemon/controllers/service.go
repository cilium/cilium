package controllers

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/daemon/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/statedb"
)

var ServiceControllerCell = cell.Module(
	"service-controller",
	"Bridges services table to ServiceManager",
	cell.Invoke(registerServiceController),
)

func registerServiceController(lc cell.Lifecycle, jobs job.Registry, scope cell.Scope, p serviceControllerParams) {
	s := &serviceController{p}
	g := jobs.NewGroup(scope)
	g.Add(job.OneShot("run", s.run))
	lc.Append(g)
}

type serviceControllerParams struct {
	cell.In

	Log           logrus.FieldLogger
	DB            *statedb.DB
	Services      statedb.Table[*tables.Service]
	Backends      statedb.Table[*tables.Backend]
	NodeAddresses statedb.Table[datapathTables.NodeAddress]
	Manager       service.ServiceManager
}

type serviceController struct {
	serviceControllerParams
}

func toSVC(addr loadbalancer.L3n4Addr, svc *tables.Service, bes []*loadbalancer.Backend) *loadbalancer.SVC {
	proxyPort := uint16(0)
	if svc.L7Redirect != nil {
		proxyPort = svc.L7Redirect.ProxyPort
	}
	healthCheckNodePort := uint16(0)
	if svc.HealthCheck != nil {
		healthCheckNodePort = svc.HealthCheck.NodePort
	}

	affinityTimeoutSec := uint32(0)
	if svc.SessionAffinity != nil {
		affinityTimeoutSec = uint32(svc.SessionAffinity.Timeout)
	}

	return &loadbalancer.SVC{
		Frontend:                  loadbalancer.L3n4AddrID{L3n4Addr: addr},
		Backends:                  bes,
		Type:                      svc.Type,
		ExtTrafficPolicy:          svc.ExtPolicy,
		IntTrafficPolicy:          svc.IntPolicy,
		NatPolicy:                 svc.NatPolicy,
		SessionAffinity:           svc.SessionAffinity != nil,
		SessionAffinityTimeoutSec: affinityTimeoutSec,
		HealthCheckNodePort:       healthCheckNodePort,
		Name:                      svc.Name,
		LoadBalancerSourceRanges:  svc.LoadBalancerSourceRanges.AsSlice(),
		L7LBProxyPort:             proxyPort,
		LoopbackHostport:          svc.LoopbackHostPort,
	}
}

func (s *serviceController) onServiceChange(txn statedb.ReadTxn, svc *tables.Service, deleted bool, rev statedb.Revision) error {
	if deleted {
		_, err := s.Manager.DeleteService(svc.L3n4Addr)
		// FIXME delete all synthesized NodePort services.
		return err
	}

	// Collect all backends for the service with matching protocols (L3&L4) and convert
	// to the SVC type.
	iter, _ := s.Backends.Get(txn, tables.BackendServiceIndex.Query(svc.Name))
	bes := statedb.Collect(
		statedb.Map(
			statedb.Filter(iter, func(be *tables.Backend) bool {
				return svc.L3n4Addr.Protocol == be.L3n4Addr.Protocol &&
					(svc.L3n4Addr.AddrCluster.Is4() && be.L3n4Addr.AddrCluster.Is4() ||
						svc.L3n4Addr.AddrCluster.Is6() && be.L3n4Addr.AddrCluster.Is6())
			}),
			(*tables.Backend).ToLoadBalancerBackend))

	_, _, err := s.Manager.UpsertService(toSVC(svc.L3n4Addr, svc, bes))
	if err != nil {
		return err
	}

	if svc.Type == loadbalancer.SVCTypeNodePort {
		// For NodePort services we synthesize new SVC for each node address.
		// The long-term idea for this is to handle this in the reconciler instead
		// and on Table[NodeAddress] changes trigger a full reconciliation to fix up.

		iter, _ := s.NodeAddresses.All(txn)
		for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
			if !addr.NodePort {
				continue
			}
			l3n4Addr := svc.L3n4Addr

			if l3n4Addr.AddrCluster.Addr().Is4() && !addr.Addr.Is4() ||
				l3n4Addr.AddrCluster.Addr().Is6() && !addr.Addr.Is6() {
				continue
			}

			l3n4Addr.AddrCluster = cmtypes.AddrClusterFrom(addr.Addr, 0)
			_, _, err := s.Manager.UpsertService(toSVC(l3n4Addr, svc, bes))
			if err != nil {
				return err
			}

		}
	}

	return err
}

func (s *serviceController) run(ctx context.Context, health cell.HealthReporter) error {
	wtxn := s.DB.WriteTxn(s.Services)
	dt, err := s.Services.DeleteTracker(wtxn, "serviceController")
	wtxn.Commit()
	if err != nil {
		return err
	}
	defer dt.Close()

	for {
		txn := s.DB.ReadTxn()
		iterateFunc := func(svc *tables.Service, deleted bool, rev statedb.Revision) {
			err := s.onServiceChange(txn, svc, deleted, rev)
			if err != nil {
				s.Log.WithError(err).Error("Service processing failed")
			}
		}
		watch := dt.Iterate(txn, iterateFunc)
		txn = nil // release reference to database snapshot

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}

}
