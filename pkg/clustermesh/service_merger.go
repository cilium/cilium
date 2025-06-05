// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

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

// MergeExternalServiceDelete implements k8s.ServiceCache.
func (sm *serviceMerger) MergeExternalServiceDelete(service *serviceStore.ClusterService) {
	name := loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	txn := sm.writer.WriteTxn()
	defer txn.Commit()
	sm.writer.DeleteBackendsOfServiceFromCluster(
		txn,
		name,
		source.ClusterMesh,
		service.ClusterID,
	)
}

// MergeExternalServiceUpdate implements k8s.ServiceCache.
func (sm *serviceMerger) MergeExternalServiceUpdate(service *serviceStore.ClusterService) {
	name := loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}

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

func ClusterServiceToBackendParams(service *serviceStore.ClusterService) (beps []loadbalancer.BackendParams) {
	for ipString, portConfig := range service.Backends {
		addrCluster := cmtypes.MustParseAddrCluster(ipString)
		for name, l4 := range portConfig {
			portNames := []string(nil)
			if name != "" {
				portNames = []string{name}
			}
			bep := loadbalancer.BackendParams{
				Address: loadbalancer.L3n4Addr{
					AddrCluster: addrCluster,
					L4Addr:      *l4,
				},
				PortNames: portNames,
				Weight:    loadbalancer.DefaultBackendWeight,
				NodeName:  "",
				ClusterID: service.ClusterID,
				State:     loadbalancer.BackendStateActive,
			}
			beps = append(beps, bep)
		}
	}
	return
}
