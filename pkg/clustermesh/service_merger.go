// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/hive/cell"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/lock"
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
	ExpConfig    loadbalancer.Config
	Writer       *writer.Writer
}

func newServiceMerger(p serviceMergerParams) ServiceMerger {
	if !p.ExpConfig.EnableExperimentalLB {
		return p.ServiceCache
	}
	return &expServiceMerger{clusterInfo: p.ClusterInfo, writer: p.Writer}
}

type expServiceMerger struct {
	clusterInfo cmtypes.ClusterInfo
	writer      *writer.Writer
}

// MergeExternalServiceDelete implements k8s.ServiceCache.
func (sm *expServiceMerger) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
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
func (sm *expServiceMerger) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
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
