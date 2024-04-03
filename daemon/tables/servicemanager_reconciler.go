package tables

import (
	"context"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

func serviceManagerReconcilerConfig(bes statedb.RWTable[*Backend], ops *serviceManagerOps) reconciler.Config[*Service] {
	return reconciler.Config[*Service]{
		FullReconcilationInterval: 30 * time.Minute, // Force update every 30 minutes
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Minute,
		IncrementalRoundSize:      300,
		GetObjectStatus:           (*Service).GetBPFStatus,
		WithObjectStatus:          (*Service).WithBPFStatus,
		RateLimiter:               rate.NewLimiter(5*time.Millisecond, 1),
		Operations:                ops,
		BatchOperations:           nil,
	}
}

type serviceManagerOps struct {
	nodeAddresses statedb.Table[datapathTables.NodeAddress]
	backends      statedb.Table[*Backend]
	manager       service.ServiceManager
}

type serviceManagerOpsParams struct {
	cell.In

	NodeAddresses statedb.Table[datapathTables.NodeAddress]
	Backends      statedb.Table[*Backend]
	Manager       service.ServiceManager
}

func newServiceManagerOps(p serviceManagerOpsParams) *serviceManagerOps {
	return &serviceManagerOps{
		backends:      p.Backends,
		nodeAddresses: p.NodeAddresses,
		manager:       p.Manager,
	}
}

// Delete implements reconciler.Operations.
func (s *serviceManagerOps) Delete(ctx context.Context, txn statedb.ReadTxn, svc *Service) error {
	_, err := s.manager.DeleteService(svc.L3n4Addr)
	// FIXME delete all synthesized NodePort services.
	return err
}

// Prune implements reconciler.Operations.
func (s *serviceManagerOps) Prune(context.Context, statedb.ReadTxn, statedb.Iterator[*Service]) error {
	// TODO "SyncWithK8sFinished". For this to be useful we need the statedb table initializers
	// that are in cilium/statedb.
	return nil
}

// Update implements reconciler.Operations.
func (ops *serviceManagerOps) Update(ctx context.Context, txn statedb.ReadTxn, svc *Service, changed *bool) error {
	// Collect all backends for the service with matching protocols (L3&L4) and convert
	// to the SVC type.
	iter, _ := ops.backends.Get(txn, BackendServiceIndex.Query(svc.Name))
	bes := statedb.Collect(
		statedb.Map(
			statedb.Filter(iter, func(be *Backend) bool {
				return svc.L3n4Addr.Protocol == be.L3n4Addr.Protocol &&
					(svc.L3n4Addr.AddrCluster.Is4() && be.L3n4Addr.AddrCluster.Is4() ||
						svc.L3n4Addr.AddrCluster.Is6() && be.L3n4Addr.AddrCluster.Is6())
			}),
			(*Backend).ToLoadBalancerBackend))

	_, _, err := ops.manager.UpsertService(toSVC(svc.L3n4Addr, svc, bes))
	if err != nil {
		return err
	}

	if svc.Type == loadbalancer.SVCTypeNodePort {
		// For NodePort services we synthesize new SVC for each node address.
		// The long-term idea for this is to handle this in the reconciler instead
		// and on Table[NodeAddress] changes trigger a full reconciliation to fix up.

		iter, _ := ops.nodeAddresses.All(txn)
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
			_, _, err := ops.manager.UpsertService(toSVC(l3n4Addr, svc, bes))
			if err != nil {
				return err
			}

		}
	}
	return nil
}

var _ reconciler.Operations[*Service] = &serviceManagerOps{}

func toSVC(addr loadbalancer.L3n4Addr, svc *Service, bes []*loadbalancer.Backend) *loadbalancer.SVC {
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
