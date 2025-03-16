// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/hive/cell"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/lock"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/source"
)

// ServiceMerger is the interface to be implemented by the owner of local
// services. The functions have to merge service updates and deletions with
// local services to provide a shared view.
type ServiceMerger interface {
	MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)
	MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)
}

type serviceMergerParams struct {
	cell.In

	ClusterInfo  cmtypes.ClusterInfo
	ServiceCache k8s.ServiceCache
	ExpConfig    experimental.Config
	Writer       *experimental.Writer
}

func newServiceMerger(p serviceMergerParams) ServiceMerger {
	if !p.ExpConfig.EnableExperimentalLB {
		return p.ServiceCache
	}
	return &expServiceMerger{clusterInfo: p.ClusterInfo, writer: p.Writer}
}

type expServiceMerger struct {
	clusterInfo cmtypes.ClusterInfo
	writer      *experimental.Writer
}

// MergeExternalServiceDelete implements k8s.ServiceCache.
func (sm *expServiceMerger) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	name := loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	txn := sm.writer.WriteTxn()
	defer txn.Commit()
	sm.writer.DeleteBackendsOfService(
		txn,
		name,
		source.ClusterMesh,
	)
}

// MergeExternalServiceUpdate implements k8s.ServiceCache.
func (sm *expServiceMerger) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	name := loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}

	txn := sm.writer.WriteTxn()
	defer txn.Commit()

	if !service.Shared {
		// The service potentially became unshared with other clusters, remove any potential
		// prior backends.
		sm.writer.DeleteBackendsOfService(txn, name, source.ClusterMesh)
		return
	}

	sm.writer.SetBackends(
		txn,
		name,
		source.ClusterMesh,
		ClusterServiceToBackendParams(service)...,
	)
}

func ClusterServiceToBackendParams(service *serviceStore.ClusterService) (beps []experimental.BackendParams) {
	for ipString, portConfig := range service.Backends {
		addrCluster, err := cmtypes.ParseAddrCluster(ipString)
		if err != nil {
			continue
		}
		for name, l4 := range portConfig {
			portNames := []string(nil)
			if name != "" {
				portNames = []string{name}
			}
			bep := experimental.BackendParams{
				Address: loadbalancer.L3n4Addr{
					AddrCluster: addrCluster,
					L4Addr:      *l4,
				},
				PortNames: portNames,
				Weight:    loadbalancer.DefaultBackendWeight,
				NodeName:  "",
				State:     loadbalancer.BackendStateActive,
			}
			beps = append(beps, bep)
		}
	}
	return
}
