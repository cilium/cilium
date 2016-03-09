package server

import (
	"errors"

	"github.com/noironetworks/cilium-net/common/types"
)

type TestDaemon struct {
	OnEndpointJoin  func(ep types.Endpoint) error
	OnEndpointLeave func(ep string) error
	OnAllocateIPs   func(containerID string) (*types.IPAMConfig, error)
	OnReleaseIPs    func(containerID string) error
	OnPing          func() (string, error)
	OnGetLabelsID   func(labels types.Labels) (int, error, bool)
	OnGetLabels     func(id int) (*types.Labels, error)
	OnGetMaxID      func() (int, error)
	OnPolicyAdd     func(path string, node types.PolicyNode) error
	OnPolicyDelete  func(path string) error
	OnPolicyGet     func(path string) (*types.PolicyNode, error)
}

func NewTestDaemon() *TestDaemon {
	return &TestDaemon{}
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

func (d TestDaemon) GetLabelsID(labels types.Labels) (int, error, bool) {
	if d.OnGetLabelsID != nil {
		return d.OnGetLabelsID(labels)
	}
	return -1, errors.New("GetLabelsID should not have been called"), false
}

func (d TestDaemon) GetLabels(id int) (*types.Labels, error) {
	if d.OnGetLabels != nil {
		return d.OnGetLabels(id)
	}
	return nil, errors.New("GetLabels should not have been called")
}

func (d TestDaemon) GetMaxID() (int, error) {
	if d.OnGetMaxID != nil {
		return d.OnGetMaxID()
	}
	return -1, errors.New("GetMaxID should not have been called")
}

func (d TestDaemon) PolicyAdd(path string, node types.PolicyNode) error {
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
