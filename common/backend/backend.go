package backend

import (
	"github.com/noironetworks/cilium-net/common/types"
)

type bpfBackend interface {
	EndpointJoin(ep types.Endpoint) error
	EndpointLeave(epID string) error
	EndpointGet(epID string) (*types.Endpoint, error)
	EndpointUpdate(epID string, opts types.EPOpts) error
}

type ipamBackend interface {
	AllocateIPs(containerID string) (*types.IPAMConfig, error)
	ReleaseIPs(containerID string) error
}

type labelBackend interface {
	PutLabels(labels types.Labels) (*types.SecCtxLabel, bool, error)
	GetLabels(uuid int) (*types.SecCtxLabel, error)
	DeleteLabelsByUUID(uuid int) error
	DeleteLabelsBySHA256(sha256sum string) error
	GetMaxID() (int, error)
}

type policyBackend interface {
	PolicyAdd(path string, node *types.PolicyNode) error
	PolicyDelete(path string) error
	PolicyGet(path string) (*types.PolicyNode, error)
}

type control interface {
	Ping() (string, error)
}

// CiliumBackend is the interface for both client and daemon.
type CiliumBackend interface {
	bpfBackend
	control
	ipamBackend
	labelBackend
	policyBackend
}
