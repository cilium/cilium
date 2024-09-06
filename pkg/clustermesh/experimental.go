package clustermesh

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/source"
)

type experimentalServiceMerger struct {
	log      *slog.Logger
	w        *experimental.Writer
	initDone func(experimental.WriteTxn)
}

func newExperimentalServiceMerger(log *slog.Logger, w *experimental.Writer) ServiceMerger {
	e := &experimentalServiceMerger{w: w}

	// Register an initializer. This marks the table as populated for the clustermesh
	// source. After the table is fully initialized pruning can be performed.
	e.initDone = w.RegisterInitializer(string(source.ClusterMesh))
	return e
}

func (e *experimentalServiceMerger) MarkInitialized() {
	txn := e.w.WriteTxn()
	e.initDone(txn)
	txn.Commit()
}

func serviceName(service *store.ClusterService) loadbalancer.ServiceName {
	return loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
}

// MergeExternalServiceDelete implements ServiceMerger.
func (e *experimentalServiceMerger) MergeExternalServiceDelete(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	txn := e.w.WriteTxn()
	defer txn.Commit()

	err := e.w.SetBackends(txn, serviceName(service), source.ClusterMesh)
	if err != nil {
		e.log.Warn("Failed to set backends", logfields.Error, err)
	}
}

// MergeExternalServiceUpdate implements ServiceMerger.
func (e *experimentalServiceMerger) MergeExternalServiceUpdate(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	backends := make([]experimental.BackendParams, 0, len(service.Backends))
	for ipString, portConfig := range service.Backends {
		addr, err := types.ParseAddrCluster(ipString)
		if err != nil {
			e.log.Warn("Failed to parse IP address", logfields.Error, err, logfields.Address, ipString)
			continue
		}

		for portName, port := range portConfig {
			l3n4Addr := loadbalancer.L3n4Addr{
				AddrCluster: addr,
				L4Addr:      *port,
			}
			backends = append(backends, experimental.BackendParams{
				L3n4Addr: l3n4Addr,
				PortName: portName,
				State:    loadbalancer.BackendStateActive,
				Weight:   loadbalancer.DefaultBackendWeight,
				NodeName: service.Hostnames[ipString],
				ZoneID:   0,
			})
		}
	}

	txn := e.w.WriteTxn()
	defer txn.Commit()

	err := e.w.SetBackends(txn, serviceName(service), source.ClusterMesh, backends...)
	if err != nil {
		e.log.Warn("Failed to set backends", logfields.Error, err)
	}
}

var _ ServiceMerger = &experimentalServiceMerger{}
