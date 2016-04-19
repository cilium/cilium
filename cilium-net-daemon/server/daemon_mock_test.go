package server

import (
	"errors"

	"github.com/noironetworks/cilium-net/common/types"
)

type TestDaemon struct {
	OnEndpointGet          func(epID string) (*types.Endpoint, error)
	OnEndpointJoin         func(ep types.Endpoint) error
	OnEndpointLeave        func(ep string) error
	OnAllocateIPs          func(containerID string) (*types.IPAMConfig, error)
	OnReleaseIPs           func(containerID string) error
	OnPing                 func() (string, error)
	OnPutLabels            func(labels types.Labels) (*types.SecCtxLabel, bool, error)
	OnGetLabels            func(id int) (*types.SecCtxLabel, error)
	OnDeleteLabelsByUUID   func(uuid int) error
	OnDeleteLabelsBySHA256 func(sha256sum string) error
	OnGetMaxID             func() (int, error)
	OnPolicyAdd            func(path string, node *types.PolicyNode) error
	OnPolicyDelete         func(path string) error
	OnPolicyGet            func(path string) (*types.PolicyNode, error)
}

func NewTestDaemon() *TestDaemon {
	return &TestDaemon{}
}

func (d TestDaemon) EndpointGet(epID string) (*types.Endpoint, error) {
	if d.EndpointGet != nil {
		return d.OnEndpointGet(epID)
	}
	return nil, errors.New("EndpointGet should not have been called")
}

func (d TestDaemon) EndpointJoin(ep types.Endpoint) error {
	if d.OnEndpointJoin != nil {
		return d.OnEndpointJoin(ep)
	}
	return errors.New("EndpointJoin should not have been called")
}

func (d TestDaemon) EndpointLeave(epID string) error {
	if d.OnEndpointLeave != nil {
		return d.OnEndpointLeave(epID)
	}
	return errors.New("EndpointLeave should not have been called")
}

func (d TestDaemon) Ping() (string, error) {
	if d.OnPing != nil {
		return d.OnPing()
	}
	return "", errors.New("Ping should not have been called")
}

func (d TestDaemon) AllocateIPs(containerID string) (*types.IPAMConfig, error) {
	if d.OnAllocateIPs != nil {
		return d.OnAllocateIPs(containerID)
	}
	return nil, errors.New("AllocateIPs should not have been called")
}

func (d TestDaemon) ReleaseIPs(containerID string) error {
	if d.OnReleaseIPs != nil {
		return d.OnReleaseIPs(containerID)
	}
	return errors.New("ReleaseIPs should not have been called")
}

func (d TestDaemon) PutLabels(labels types.Labels) (*types.SecCtxLabel, bool, error) {
	if d.OnPutLabels != nil {
		return d.OnPutLabels(labels)
	}
	return nil, false, errors.New("GetLabelsID should not have been called")
}

func (d TestDaemon) GetLabels(id int) (*types.SecCtxLabel, error) {
	if d.OnGetLabels != nil {
		return d.OnGetLabels(id)
	}
	return nil, errors.New("GetLabels should not have been called")
}

func (d TestDaemon) DeleteLabelsByUUID(uuid int) error {
	if d.OnDeleteLabelsByUUID != nil {
		return d.OnDeleteLabelsByUUID(uuid)
	}
	return errors.New("DeleteLabelsByUUID should not have been called")
}

func (d TestDaemon) DeleteLabelsBySHA256(sha256sum string) error {
	if d.OnDeleteLabelsBySHA256 != nil {
		return d.OnDeleteLabelsBySHA256(sha256sum)
	}
	return errors.New("DeleteLabelsBySHA256 should not have been called")
}

func (d TestDaemon) GetMaxID() (int, error) {
	if d.OnGetMaxID != nil {
		return d.OnGetMaxID()
	}
	return -1, errors.New("GetMaxID should not have been called")
}

func (d TestDaemon) PolicyAdd(path string, node *types.PolicyNode) error {
	if d.PolicyAdd != nil {
		return d.PolicyAdd(path, node)
	}
	return errors.New("PolicyAdd should not have been called")
}

func (d TestDaemon) PolicyDelete(path string) error {
	if d.PolicyDelete != nil {
		return d.PolicyDelete(path)
	}
	return errors.New("PolicyDelete should not have been called")
}

func (d TestDaemon) PolicyGet(path string) (*types.PolicyNode, error) {
	if d.PolicyGet != nil {
		return d.PolicyGet(path)
	}
	return nil, errors.New("PolicyGet should not have been called")
}
