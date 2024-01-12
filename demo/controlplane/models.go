package controlplane

import (
	"net/netip"
)

type Source string

const (
	SourceK8s = "k8s"
	SourceAPI = "api"
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

type PortAndProtocol struct {
	Port     uint16
	Protocol string
}

type Endpoint struct {
	Source  Source
	Service string
	Addrs   []netip.Addr
	Ports   []PortAndProtocol
}
