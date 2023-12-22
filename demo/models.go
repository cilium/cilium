package main

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
	Ports       []int
}

func parseService(obj any) (*Service, bool) {
	s, ok := obj.(*v1.Service)
	if !ok {
		return nil, false
	}
	return &Service{
		Source:      SourceK8s,
		ServiceType: ServiceType(s.Spec.Type),
		ClusterIP:   netip.MustParseAddr(s.Spec.ClusterIP),
		Ports:       parsePorts(s.Spec.Ports),
	}, true
}

func parsePorts(ports []v1.ServicePort) (out []int) {
	for _, p := range ports {
		out = append(out, int(p.Port))
	}
	return out
}

type Backend struct {
	Source  Source
	Service string
	Addrs   []netip.Addr
	Ports   []int
}

func parseEndpoints(obj any) (*Backend, bool) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		return nil, false
	}

	be := &Backend{
		Source:  SourceK8s,
		Service: ep.Namespace + "/" + ep.Name,
	}
	for _, subset := range ep.Subsets {
		for _, port := range subset.Ports {
			be.Ports = append(be.Ports, int(port.Port))
		}

		for _, addr := range subset.Addresses {
			be.Addrs = append(be.Addrs, netip.MustParseAddr(addr.IP))
		}
	}
	return be, true
}
