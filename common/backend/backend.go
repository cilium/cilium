package backend

import (
	"github.com/noironetworks/cilium-net/common/types"
)

type bpfBackend interface {
	EndpointJoin(ep types.Endpoint) error
	EndpointLeave(epID string) error
}

type ipamBackend interface {
	AllocateIPs(containerID string) (*types.IPAMConfig, error)
	ReleaseIPs(containerID string) error
}

type control interface {
	Ping() (string, error)
}

type CiliumBackend interface {
	bpfBackend
	control
	ipamBackend
}
