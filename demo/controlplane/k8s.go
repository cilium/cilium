package controlplane

import (
	"net/netip"
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reflector"
	v1 "k8s.io/api/core/v1"
)

var k8sCell = cell.Module(
	"k8s-reflectors",
	"Reflects K8s objects to tables",

	cell.ProvidePrivate(
		servicesConfig,
		endpointsConfig,
	),
	reflector.KubernetesCell[*Service](),
	reflector.KubernetesCell[*Endpoint](),
)

func servicesConfig(cs client.Clientset, t statedb.RWTable[*Service]) reflector.KubernetesConfig[*Service] {
	return reflector.KubernetesConfig[*Service]{
		BufferSize:     100,
		BufferWaitTime: 100 * time.Millisecond,
		ListerWatcher:  utils.ListerWatcherFromTyped[*v1.ServiceList](cs.CoreV1().Services("default")),
		Table:          t,
		Transform:      parseK8sService,
	}
}

func parseK8sService(obj any) (*Service, bool) {
	s, ok := obj.(*v1.Service)
	if !ok {
		return nil, false
	}
	if len(s.Spec.Ports) == 0 {
		return nil, false
	}
	// For sake of example we only do one port&protocol
	port := s.Spec.Ports[0]
	proto := string(port.Protocol)
	if proto == "" {
		proto = "TCP"
	}

	return &Service{
		Source:      SourceK8s,
		Name:        s.Namespace + "/" + s.Name,
		ServiceType: ServiceType(s.Spec.Type),
		ClusterIP:   netip.MustParseAddr(s.Spec.ClusterIP),
		Port:        uint16(port.Port),
		Protocol:    proto,
	}, true
}

func endpointsConfig(cs client.Clientset, t statedb.RWTable[*Endpoint]) reflector.KubernetesConfig[*Endpoint] {
	return reflector.KubernetesConfig[*Endpoint]{
		BufferSize:     100,
		BufferWaitTime: 100 * time.Millisecond,
		ListerWatcher:  utils.ListerWatcherFromTyped[*v1.EndpointsList](cs.CoreV1().Endpoints("default")),
		Table:          t,
		Transform:      parseK8sEndpoints,
	}
}

func parseK8sEndpoints(obj any) (*Endpoint, bool) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		return nil, false
	}

	be := &Endpoint{
		Source:  SourceK8s,
		Service: ep.Namespace + "/" + ep.Name,
	}
	for _, subset := range ep.Subsets {
		for _, port := range subset.Ports {
			be.Ports = append(be.Ports, PortAndProtocol{uint16(port.Port), string(port.Protocol)})
		}

		for _, addr := range subset.Addresses {
			be.Addrs = append(be.Addrs, netip.MustParseAddr(addr.IP))
		}
	}
	return be, true
}
