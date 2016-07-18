package server

import (
	"errors"
	"net"

	"github.com/noironetworks/cilium-net/common/ipam"
	"github.com/noironetworks/cilium-net/common/types"

	"github.com/gorilla/websocket"
)

type TestDaemon struct {
	OnEndpointGet               func(epID uint16) (*types.Endpoint, error)
	OnEndpointGetByDockerEPID   func(dockerEPID string) (*types.Endpoint, error)
	OnEndpointsGet              func() ([]types.Endpoint, error)
	OnEndpointJoin              func(ep types.Endpoint) error
	OnEndpointLeave             func(epID uint16) error
	OnEndpointLeaveByDockerEPID func(dockerEPID string) error
	OnEndpointUpdate            func(epID uint16, opts types.OptionMap) error
	OnEndpointSave              func(ep types.Endpoint) error
	OnEndpointLabelsGet         func(epID uint16) (*types.OpLabels, error)
	OnEndpointLabelsUpdate      func(epID uint16, op types.LabelOP, labels types.Labels) error
	OnGetIPAMConf               func(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error)
	OnAllocateIP                func(ipamType ipam.IPAMType, opts ipam.IPAMReq) (*ipam.IPAMRep, error)
	OnReleaseIP                 func(ipamType ipam.IPAMType, opts ipam.IPAMReq) error
	OnPing                      func() (*types.PingResponse, error)
	OnUpdate                    func(opts types.OptionMap) error
	OnSyncState                 func(path string, clean bool) error
	OnPutLabels                 func(labels types.Labels, contID string) (*types.SecCtxLabel, bool, error)
	OnGetLabels                 func(id uint32) (*types.SecCtxLabel, error)
	OnGetLabelsBySHA256         func(sha256sum string) (*types.SecCtxLabel, error)
	OnDeleteLabelsByUUID        func(uuid uint32, contID string) error
	OnDeleteLabelsBySHA256      func(sha256sum, contID string) error
	OnGetMaxID                  func() (uint32, error)
	OnPolicyAdd                 func(path string, node *types.PolicyNode) error
	OnPolicyDelete              func(path string) error
	OnPolicyGet                 func(path string) (*types.PolicyNode, error)
	OnPolicyCanConsume          func(sc *types.SearchContext) (*types.SearchContextReply, error)
	OnGetUIIP                   func() (*net.TCPAddr, error)
	OnRegisterUIListener        func(conn *websocket.Conn) (chan types.UIUpdateMsg, error)
}

func NewTestDaemon() *TestDaemon {
	return &TestDaemon{}
}

func (d TestDaemon) EndpointGet(epID uint16) (*types.Endpoint, error) {
	if d.OnEndpointGet != nil {
		return d.OnEndpointGet(epID)
	}
	return nil, errors.New("EndpointGet should not have been called")
}

func (d TestDaemon) EndpointGetByDockerEPID(dockerEPID string) (*types.Endpoint, error) {
	if d.OnEndpointGetByDockerEPID != nil {
		return d.OnEndpointGetByDockerEPID(dockerEPID)
	}
	return nil, errors.New("EndpointGetByDockerEPID should not have been called")
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

func (d TestDaemon) EndpointUpdate(epID uint16, opts types.OptionMap) error {
	if d.OnEndpointUpdate != nil {
		return d.OnEndpointUpdate(epID, opts)
	}
	return errors.New("EndpointUpdate should not have been called")
}

func (d TestDaemon) EndpointLeave(epID uint16) error {
	if d.OnEndpointLeave != nil {
		return d.OnEndpointLeave(epID)
	}
	return errors.New("EndpointLeave should not have been called")
}

func (d TestDaemon) EndpointLeaveByDockerEPID(dockerEPID string) error {
	if d.OnEndpointLeaveByDockerEPID != nil {
		return d.OnEndpointLeaveByDockerEPID(dockerEPID)
	}
	return errors.New("OnEndpointLeaveByDockerEPID should not have been called")
}

func (d TestDaemon) EndpointSave(ep types.Endpoint) error {
	if d.OnEndpointSave != nil {
		return d.OnEndpointSave(ep)
	}
	return errors.New("EndpointSave should not have been called")
}

func (d TestDaemon) EndpointLabelsGet(epID uint16) (*types.OpLabels, error) {
	if d.OnEndpointLabelsGet != nil {
		return d.OnEndpointLabelsGet(epID)
	}
	return nil, errors.New("EndpointLabelsGet should not have been called")
}

func (d TestDaemon) EndpointLabelsUpdate(epID uint16, op types.LabelOP, labels types.Labels) error {
	if d.OnEndpointLabelsUpdate != nil {
		return d.OnEndpointLabelsUpdate(epID, op, labels)
	}
	return errors.New("EndpointLabelsUpdate should not have been called")
}

func (d TestDaemon) Ping() (*types.PingResponse, error) {
	if d.OnPing != nil {
		return d.OnPing()
	}
	return nil, errors.New("Ping should not have been called")
}

func (d TestDaemon) Update(opts types.OptionMap) error {
	if d.OnUpdate != nil {
		return d.OnUpdate(opts)
	}
	return errors.New("Update should not have been called")
}

func (d TestDaemon) SyncState(path string, clean bool) error {
	if d.OnSyncState != nil {
		return d.OnSyncState(path, clean)
	}
	return errors.New("SyncState should not have been called")
}

func (d TestDaemon) GetIPAMConf(ipamType ipam.IPAMType, opts ipam.IPAMReq) (*ipam.IPAMConfigRep, error) {
	if d.OnGetIPAMConf != nil {
		return d.OnGetIPAMConf(ipamType, opts)
	}
	return nil, errors.New("GetIPAMConf should not have been called")
}

func (d TestDaemon) AllocateIP(ipamType ipam.IPAMType, opts ipam.IPAMReq) (*ipam.IPAMRep, error) {
	if d.OnAllocateIP != nil {
		return d.OnAllocateIP(ipamType, opts)
	}
	return nil, errors.New("AllocateIP should not have been called")
}

func (d TestDaemon) ReleaseIP(ipamType ipam.IPAMType, opts ipam.IPAMReq) error {
	if d.OnReleaseIP != nil {
		return d.OnReleaseIP(ipamType, opts)
	}
	return errors.New("ReleaseIP should not have been called")
}

func (d TestDaemon) PutLabels(labels types.Labels, contID string) (*types.SecCtxLabel, bool, error) {
	if d.OnPutLabels != nil {
		return d.OnPutLabels(labels, contID)
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

func (d TestDaemon) DeleteLabelsByUUID(uuid uint32, contID string) error {
	if d.OnDeleteLabelsByUUID != nil {
		return d.OnDeleteLabelsByUUID(uuid, contID)
	}
	return errors.New("DeleteLabelsByUUID should not have been called")
}

func (d TestDaemon) DeleteLabelsBySHA256(sha256sum, contID string) error {
	if d.OnDeleteLabelsBySHA256 != nil {
		return d.OnDeleteLabelsBySHA256(sha256sum, contID)
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

func (d TestDaemon) GetUIIP() (*net.TCPAddr, error) {
	if d.OnGetUIIP != nil {
		return d.OnGetUIIP()
	}
	return nil, errors.New("GetUIIP should not have been called")
}

func (d TestDaemon) RegisterUIListener(conn *websocket.Conn) (chan types.UIUpdateMsg, error) {
	if d.OnRegisterUIListener != nil {
		return d.OnRegisterUIListener(conn)
	}
	return nil, errors.New("RegisterUIListener should not have been called")
}
