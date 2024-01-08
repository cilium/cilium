package controlplane

import (
	"net/netip"

	v1 "k8s.io/api/core/v1"
)

type Source string

const (
	SourceK8s = "k8s"
)

type ServiceType string

type Service struct {
	Name        string
	Source      Source
	ServiceType ServiceType
	ClusterIP   netip.Addr

	// For sake of example we only do one port&protocol
	Port     uint16
	Protocol string
}

func parseService(obj any) (*Service, bool) {
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

type PortAndProtocol struct {
	Port     uint16
	Protocol string
}

type Endpoint struct {
	Source   Source
	Service  string
	Addrs    []netip.Addr
	Ports    []PortAndProtocol
	Protocol string
}

func parseEndpoints(obj any) (*Endpoint, bool) {
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
