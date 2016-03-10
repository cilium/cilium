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

type labelBackend interface {
	GetLabelsID(labels types.Labels) (int, bool, error)
	GetLabels(id int) (*types.Labels, error)
	GetMaxID() (int, error)
}

type policyBackend interface {
	PolicyAdd(path string, node types.PolicyNode) error
	PolicyDelete(path string) error
	PolicyGet(path string) (*types.PolicyNode, error)
}

type control interface {
	Ping() (string, error)
}

type CiliumBackend interface {
	bpfBackend
	control
	ipamBackend
	labelBackend
	policyBackend
}
