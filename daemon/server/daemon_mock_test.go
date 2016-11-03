//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package server

import (
	"errors"
	"net"

	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"

	"github.com/gorilla/websocket"
)

type TestDaemon struct {
	OnEndpointGet               func(epID uint16) (*types.Endpoint, error)
	OnEndpointGetByDockerEPID   func(dockerEPID string) (*types.Endpoint, error)
	OnEndpointGetByDockerID     func(dockerID string) (*types.Endpoint, error)
	OnEndpointsGet              func() ([]types.Endpoint, error)
	OnEndpointJoin              func(ep types.Endpoint) error
	OnEndpointLeave             func(epID uint16) error
	OnEndpointLeaveByDockerEPID func(dockerEPID string) error
	OnEndpointUpdate            func(epID uint16, opts types.OptionMap) error
	OnEndpointSave              func(ep types.Endpoint) error
	OnEndpointLabelsGet         func(epID uint16) (*types.OpLabels, error)
	OnEndpointLabelsUpdate      func(epID uint16, labelOp types.LabelOp) error
	OnGetIPAMConf               func(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error)
	OnAllocateIP                func(ipamType ipam.IPAMType, opts ipam.IPAMReq) (*ipam.IPAMRep, error)
	OnReleaseIP                 func(ipamType ipam.IPAMType, opts ipam.IPAMReq) error
	OnPing                      func() (*types.PingResponse, error)
	OnGlobalStatus              func() (*types.StatusResponse, error)
	OnUpdate                    func(opts types.OptionMap) error
	OnSyncState                 func(path string, clean bool) error
	OnPutLabels                 func(labels types.Labels, contID string) (*types.SecCtxLabel, bool, error)
	OnGetLabels                 func(id uint32) (*types.SecCtxLabel, error)
	OnGetLabelsBySHA256         func(sha256sum string) (*types.SecCtxLabel, error)
	OnDeleteLabelsByUUID        func(uuid uint32, contID string) error
	OnDeleteLabelsBySHA256      func(sha256sum, contID string) error
	OnGetMaxLabelID             func() (uint32, error)
	OnPolicyAdd                 func(path string, node *types.PolicyNode) error
	OnPolicyDelete              func(path string) error
	OnPolicyGet                 func(path string) (*types.PolicyNode, error)
	OnPolicyCanConsume          func(sc *types.SearchContext) (*types.SearchContextReply, error)
	OnSVCAdd                    func(fe types.L3n4AddrID, be []types.L3n4Addr, addRevNAT bool) error
	OnSVCDelete                 func(feL3n4 types.L3n4Addr) error
	OnSVCDeleteBySHA256Sum      func(feL3n4SHA256Sum string) error
	OnSVCGet                    func(feL3n4 types.L3n4Addr) (*types.LBSVC, error)
	OnSVCGetBySHA256Sum         func(feL3n4SHA256Sum string) (*types.LBSVC, error)
	OnSVCDump                   func() ([]types.LBSVC, error)
	OnRevNATAdd                 func(id types.ServiceID, revNAT types.L3n4Addr) error
	OnRevNATDelete              func(id types.ServiceID) error
	OnRevNATGet                 func(id types.ServiceID) (*types.L3n4Addr, error)
	OnRevNATDump                func() ([]types.L3n4AddrID, error)
	OnGetUIIP                   func() (*net.TCPAddr, error)
	OnGetUIPath                 func() (string, error)
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

func (d TestDaemon) EndpointGetByDockerID(dockerID string) (*types.Endpoint, error) {
	if d.OnEndpointGetByDockerID != nil {
		return d.OnEndpointGetByDockerID(dockerID)
	}
	return nil, errors.New("EndpointGetByDockerID should not have been called")
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

func (d TestDaemon) EndpointLabelsUpdate(epID uint16, labelOp types.LabelOp) error {
	if d.OnEndpointLabelsUpdate != nil {
		return d.OnEndpointLabelsUpdate(epID, labelOp)
	}
	return errors.New("EndpointLabelsUpdate should not have been called")
}

func (d TestDaemon) Ping() (*types.PingResponse, error) {
	if d.OnPing != nil {
		return d.OnPing()
	}
	return nil, errors.New("Ping should not have been called")
}

func (d TestDaemon) GlobalStatus() (*types.StatusResponse, error) {
	if d.OnGlobalStatus != nil {
		return d.OnGlobalStatus()
	}
	return nil, errors.New("GlobalStatus should not have been called")
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

func (d TestDaemon) GetMaxLabelID() (uint32, error) {
	if d.OnGetMaxLabelID != nil {
		return d.OnGetMaxLabelID()
	}
	return 0, errors.New("GetMaxLabelID should not have been called")
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

func (d TestDaemon) SVCAdd(fe types.L3n4AddrID, be []types.L3n4Addr, addRevNAT bool) error {
	if d.OnSVCAdd != nil {
		return d.OnSVCAdd(fe, be, addRevNAT)
	}
	return errors.New("SVCAdd should not have been called")
}

func (d TestDaemon) SVCDelete(feL3n4 types.L3n4Addr) error {
	if d.OnSVCDelete != nil {
		return d.OnSVCDelete(feL3n4)
	}
	return errors.New("SVCDelete should not have been called")
}

func (d TestDaemon) SVCDeleteBySHA256Sum(feL3n4SHA256Sum string) error {
	if d.OnSVCDeleteBySHA256Sum != nil {
		return d.OnSVCDeleteBySHA256Sum(feL3n4SHA256Sum)
	}
	return errors.New("SVCDeleteBySHA256Sum should not have been called")
}

func (d TestDaemon) SVCGet(feL3n4 types.L3n4Addr) (*types.LBSVC, error) {
	if d.OnSVCGet != nil {
		return d.OnSVCGet(feL3n4)
	}
	return nil, errors.New("SVCGet should not have been called")
}

func (d TestDaemon) SVCGetBySHA256Sum(feL3n4SHA256Sum string) (*types.LBSVC, error) {
	if d.OnSVCGetBySHA256Sum != nil {
		return d.OnSVCGetBySHA256Sum(feL3n4SHA256Sum)
	}
	return nil, errors.New("SVCGetBySHA256Sum should not have been called")
}

func (d TestDaemon) SVCDump() ([]types.LBSVC, error) {
	if d.OnSVCDump != nil {
		return d.OnSVCDump()
	}
	return nil, errors.New("SVCDump should not have been called")
}

func (d TestDaemon) RevNATAdd(id types.ServiceID, revNAT types.L3n4Addr) error {
	if d.OnRevNATAdd != nil {
		return d.OnRevNATAdd(id, revNAT)
	}
	return errors.New("RevNATAdd should not have been called")
}

func (d TestDaemon) RevNATDelete(id types.ServiceID) error {
	if d.OnRevNATDelete != nil {
		return d.OnRevNATDelete(id)
	}
	return errors.New("RevNATDelete should not have been called")
}

func (d TestDaemon) RevNATGet(id types.ServiceID) (*types.L3n4Addr, error) {
	if d.OnRevNATGet != nil {
		return d.OnRevNATGet(id)
	}
	return nil, errors.New("RevNATGet should not have been called")
}

func (d TestDaemon) RevNATDump() ([]types.L3n4AddrID, error) {
	if d.OnRevNATDump != nil {
		return d.OnRevNATDump()
	}
	return nil, errors.New("RevNATDump should not have been called")
}

func (d TestDaemon) GetUIIP() (*net.TCPAddr, error) {
	if d.OnGetUIIP != nil {
		return d.OnGetUIIP()
	}
	return nil, errors.New("GetUIIP should not have been called")
}

func (d TestDaemon) GetUIPath() (string, error) {
	if d.OnGetUIPath != nil {
		return d.OnGetUIPath()
	}
	return "", errors.New("GetUIPath should not have been called")
}

func (d TestDaemon) RegisterUIListener(conn *websocket.Conn) (chan types.UIUpdateMsg, error) {
	if d.OnRegisterUIListener != nil {
		return d.OnRegisterUIListener(conn)
	}
	return nil, errors.New("RegisterUIListener should not have been called")
}
