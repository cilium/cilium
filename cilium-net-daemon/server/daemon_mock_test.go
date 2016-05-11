package server

import (
	"errors"

	"github.com/noironetworks/cilium-net/common/types"
)

type TestDaemon struct {
	OnEndpointGet          func(epID string) (*types.Endpoint, error)
	OnEndpointsGet         func() ([]types.Endpoint, error)
	OnEndpointJoin         func(ep types.Endpoint) error
	OnEndpointLeave        func(ep string) error
	OnEndpointUpdate       func(ep string, opts types.EPOpts) error
	OnAllocateIP           func(ipamType types.IPAMType, opts types.IPAMReq) (*types.IPAMConfig, error)
	OnReleaseIP            func(ipamType types.IPAMType, opts types.IPAMReq) error
	OnPing                 func() (*types.PingResponse, error)
	OnSyncState            func(path string, clean bool) error
	OnPutLabels            func(labels types.Labels) (*types.SecCtxLabel, bool, error)
	OnGetLabels            func(id uint32) (*types.SecCtxLabel, error)
	OnGetLabelsBySHA256    func(sha256sum string) (*types.SecCtxLabel, error)
	OnDeleteLabelsByUUID   func(uuid uint32) error
	OnDeleteLabelsBySHA256 func(sha256sum string) error
	OnGetMaxID             func() (uint32, error)
	OnPolicyAdd            func(path string, node *types.PolicyNode) error
	OnPolicyDelete         func(path string) error
	OnPolicyGet            func(path string) (*types.PolicyNode, error)
	OnPolicyCanConsume     func(sc *types.SearchContext) (*types.SearchContextReply, error)
}

func NewTestDaemon() *TestDaemon {
	return &TestDaemon{}
}

func (d TestDaemon) EndpointGet(epID string) (*types.Endpoint, error) {
	if d.OnEndpointGet != nil {
		return d.OnEndpointGet(epID)
	}
	return nil, errors.New("EndpointGet should not have been called")
}

func (d TestDaemon) EndpointsGet() ([]types.Endpoint, error) {
	if d.OnEndpointsGet != nil {
		return d.OnEndpointsGet()
	}
	return nil, errors.New("EndpointsGet should not have been called")
}

func (d TestDaemon) EndpointJoin(ep types.Endpoint) error {
	if d.OnEndpointJoin != nil {
		return d.OnEndpointJoin(ep)
	}
	return errors.New("EndpointJoin should not have been called")
}

func (d TestDaemon) EndpointUpdate(ep string, opts types.EPOpts) error {
	if d.OnEndpointUpdate != nil {
		return d.OnEndpointUpdate(ep, opts)
	}
	return errors.New("EndpointUpdate should not have been called")
}

func (d TestDaemon) EndpointLeave(epID string) error {
	if d.OnEndpointLeave != nil {
		return d.OnEndpointLeave(epID)
	}
	return errors.New("EndpointLeave should not have been called")
}

func (d TestDaemon) Ping() (*types.PingResponse, error) {
	if d.OnPing != nil {
		return d.OnPing()
	}
	return nil, errors.New("Ping should not have been called")
}

func (d TestDaemon) SyncState(path string, clean bool) error {
	if d.OnSyncState != nil {
		return d.OnSyncState(path, clean)
	}
	return errors.New("SyncState should not have been called")
}

func (d TestDaemon) AllocateIP(ipamType types.IPAMType, opts types.IPAMReq) (*types.IPAMConfig, error) {
	if d.OnAllocateIP != nil {
		return d.OnAllocateIP(ipamType, opts)
	}
	return nil, errors.New("AllocateIP should not have been called")
}

func (d TestDaemon) ReleaseIP(ipamType types.IPAMType, opts types.IPAMReq) error {
	if d.OnReleaseIP != nil {
		return d.OnReleaseIP(ipamType, opts)
	}
	return errors.New("ReleaseIP should not have been called")
}

func (d TestDaemon) PutLabels(labels types.Labels) (*types.SecCtxLabel, bool, error) {
	if d.OnPutLabels != nil {
		return d.OnPutLabels(labels)
	}
	return nil, false, errors.New("GetLabelsID should not have been called")
}

func (d TestDaemon) GetLabels(id uint32) (*types.SecCtxLabel, error) {
	if d.OnGetLabels != nil {
		return d.OnGetLabels(id)
	}
	return nil, errors.New("GetLabels should not have been called")
}

func (d TestDaemon) GetLabelsBySHA256(sha256sum string) (*types.SecCtxLabel, error) {
	if d.OnGetLabelsBySHA256 != nil {
		return d.OnGetLabelsBySHA256(sha256sum)
	}
	return nil, errors.New("GetLabelsBySHA256 should not have been called")
}

func (d TestDaemon) DeleteLabelsByUUID(uuid uint32) error {
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

func (d TestDaemon) GetMaxID() (uint32, error) {
	if d.OnGetMaxID != nil {
		return d.OnGetMaxID()
	}
	return 0, errors.New("GetMaxID should not have been called")
}

func (d TestDaemon) PolicyAdd(path string, node *types.PolicyNode) error {
	if d.OnPolicyAdd != nil {
		return d.OnPolicyAdd(path, node)
	}
	return errors.New("PolicyAdd should not have been called")
}

func (d TestDaemon) PolicyDelete(path string) error {
	if d.OnPolicyDelete != nil {
		return d.OnPolicyDelete(path)
	}
	return errors.New("PolicyDelete should not have been called")
}

func (d TestDaemon) PolicyGet(path string) (*types.PolicyNode, error) {
	if d.OnPolicyGet != nil {
		return d.OnPolicyGet(path)
	}
	return nil, errors.New("PolicyGet should not have been called")
}

func (d TestDaemon) PolicyCanConsume(sc *types.SearchContext) (*types.SearchContextReply, error) {
	if d.OnPolicyCanConsume != nil {
		return d.OnPolicyCanConsume(sc)
	}
	return nil, errors.New("PolicyCanConsume should not have been called")
}
