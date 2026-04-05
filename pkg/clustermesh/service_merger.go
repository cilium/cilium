// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/source"
)

// ServiceMerger is the interface to be implemented by the owner of local
// services. The functions have to merge service updates and deletions with
// local services to provide a shared view.
type ServiceMerger interface {
	MergeExternalServiceUpdate(service *serviceStore.ClusterService)
	MergeExternalServiceDelete(service *serviceStore.ClusterService)
}

type serviceMergerParams struct {
	cell.In

	ClusterInfo cmtypes.ClusterInfo
	CMConfig    common.Config
	LBConfig    loadbalancer.Config
	Writer      *writer.Writer
}

func newServiceMerger(p serviceMergerParams) ServiceMerger {
	return &serviceMerger{clusterInfo: p.ClusterInfo, writer: p.Writer}
}

// registerServicesInitialized adds a job to wait for the ClusterMesh services to be synchronized
// before marking the load-balancing tables as initialized.
func registerServicesInitialized(jobs job.Group, cm *ClusterMesh, sm ServiceMerger, w *writer.Writer) {
	if cm == nil {
		return
	}
	markDone := w.RegisterInitializer("clustermesh")
	jobs.Add(
		job.OneShot(
			"services-initialized",
			func(ctx context.Context, health cell.Health) error {
				err := cm.ServicesSynced(ctx)
				txn := w.WriteTxn()
				markDone(txn)
				txn.Commit()
				return err
			}))
}

type serviceMerger struct {
	clusterInfo cmtypes.ClusterInfo
	writer      *writer.Writer
}

func (sm *serviceMerger) MergeExternalServiceDelete(service *serviceStore.ClusterService) {
	name := loadbalancer.NewServiceName(service.Namespace, service.Name)
	txn := sm.writer.WriteTxn()
	defer txn.Commit()
	sm.writer.DeleteBackendsOfServiceFromCluster(
		txn,
		name,
		source.ClusterMesh,
		service.ClusterID,
	)
}

func (sm *serviceMerger) MergeExternalServiceUpdate(service *serviceStore.ClusterService) {
	name := loadbalancer.NewServiceName(service.Namespace, service.Name)

	txn := sm.writer.WriteTxn()
	defer txn.Commit()

	sm.writer.SetBackendsOfCluster(
		txn,
		name,
		source.ClusterMesh,
		service.ClusterID,
		ClusterServiceToBackendParams(service)...,
	)
}

func ClusterServiceToBackendParams(service *serviceStore.ClusterService) (beps []loadbalancer.Backend) {
	for ipString, portConfig := range service.Backends {
		addrCluster := cmtypes.MustParseAddrCluster(ipString)
		var backendZone *loadbalancer.BackendZone
		if zone, ok := service.Zones[ipString]; ok {
			backendZone = ptr.To(zone.ToLBBackendZone())
		}

		currentIdx := len(beps)
		for name, l4 := range portConfig {
			currentBeps := beps[currentIdx:]
			// Cilium loadbalancer needs to encode a Service with multiple port names
			// for the same target port with a single loadbalancer.Backend with multiple
			// port names. The clustermesh service data on the other end contains all the
			// ports as distinct entries so we need to de-duplicate those.
			idx := slices.IndexFunc(currentBeps, func(b loadbalancer.Backend) bool {
				return b.Address.Protocol() == l4.Protocol && b.Address.Port() == l4.Port
			})
			// No existing backend for this L4 address, create a new one.
			if idx == -1 {
				beps = append(beps, loadbalancer.Backend{
					Address: loadbalancer.NewL3n4Addr(
						l4.Protocol,
						addrCluster,
						l4.Port,
						loadbalancer.ScopeExternal,
					),
					Weight:    loadbalancer.DefaultBackendWeight,
					NodeName:  "",
					ClusterID: service.ClusterID,
					State:     loadbalancer.BackendStateActive,
					Zone:      backendZone,
				})
				idx = len(currentBeps)
			}
			if name != "" {
				beps[currentIdx+idx].PortNames = append(beps[currentIdx+idx].PortNames, name)
			}
		}
	}

	// Sort port names to ensure a stable order since map iteration is
	// non-deterministic, which is required for DeepEqual comparisons.
	for _, bep := range beps {
		slices.Sort(bep.PortNames)
	}

	return
}
