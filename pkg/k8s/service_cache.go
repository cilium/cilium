package k8s

import (
	"net"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

type ServiceCache interface {
	EnsureService(svcID ServiceID, swg *lock.StoppableWaitGroup) bool

	GetServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr

	MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)

	MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)

	MergeClusterServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)

	MergeClusterServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)

	GetServiceAddrsWithType(svcID ServiceID, svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int)

	GetServiceFrontendIP(svcID ServiceID, svcType loadbalancer.SVCType) net.IP

	GetEndpointsOfService(svcID ServiceID) *Endpoints

	LocalServices() sets.Set[ServiceID]

	UniqueServiceFrontends() FrontendList

	GetNodeAddressing() types.NodeAddressing

	ForEachService(yield func(svcID ServiceID, svc *Service, eps *Endpoints) bool)

	DebugStatus() string
}

type FrontendList map[string]struct{}
