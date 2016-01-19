package backend

import (
	"github.com/noironetworks/cilium-net/common/types"
)

type bpfBackend interface {
	EndpointJoin(ep types.Endpoint) error
	EndpointLeave(ep types.Endpoint) error
}

type control interface {
	Ping() (string, error)
}

type CiliumBackend interface {
	bpfBackend
	control
}
