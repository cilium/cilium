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
package backend

import (
	"net"

	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"

	"github.com/gorilla/websocket"
)

type bpfBackend interface {
	EndpointJoin(ep types.Endpoint) error
	EndpointLeave(epID uint16) error
	EndpointLeaveByDockerEPID(dockerEPID string) error
	EndpointGet(epID uint16) (*types.Endpoint, error)
	EndpointGetByDockerEPID(dockerEPID string) (*types.Endpoint, error)
	EndpointGetByDockerID(dockerID string) (*types.Endpoint, error)
	EndpointsGet() ([]types.Endpoint, error)
	EndpointUpdate(epID uint16, opts types.OptionMap) error
	EndpointSave(ep types.Endpoint) error
	EndpointLabelsGet(epID uint16) (*types.OpLabels, error)
	EndpointLabelsUpdate(epID uint16, labelOp types.LabelOp) error
}

type ipamBackend interface {
	GetIPAMConf(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error)
	AllocateIP(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMRep, error)
	ReleaseIP(ipamType ipam.IPAMType, options ipam.IPAMReq) error
}

type labelBackend interface {
	PutLabels(labels types.Labels, contĨD string) (*types.SecCtxLabel, bool, error)
	GetLabels(uuid uint32) (*types.SecCtxLabel, error)
	GetLabelsBySHA256(sha256sum string) (*types.SecCtxLabel, error)
	DeleteLabelsByUUID(uuid uint32, contĨD string) error
	DeleteLabelsBySHA256(sha256sum, contID string) error
	GetMaxLabelID() (uint32, error)
}

type policyBackend interface {
	PolicyAdd(path string, node *types.PolicyNode) error
	PolicyDelete(path string) error
	PolicyGet(path string) (*types.PolicyNode, error)
	PolicyCanConsume(ctx *types.SearchContext) (*types.SearchContextReply, error)
}

type control interface {
	Ping() (*types.PingResponse, error)
	Update(opts types.OptionMap) error
	SyncState(path string, clean bool) error
	GlobalStatus() (*types.StatusResponse, error)
}

type ui interface {
	GetUIIP() (*net.TCPAddr, error)
	GetUIPath() (string, error)
	RegisterUIListener(conn *websocket.Conn) (chan types.UIUpdateMsg, error)
}

type LBBackend interface {
	SVCAdd(fe types.L3n4AddrID, be []types.L3n4Addr, addRevNAT bool) error
	SVCDelete(feL3n4 types.L3n4Addr) error
	SVCDeleteBySHA256Sum(feL3n4SHA256Sum string) error
	SVCDeleteAll() error
	SVCGet(feL3n4 types.L3n4Addr) (*types.LBSVC, error)
	SVCGetBySHA256Sum(feL3n4SHA256Sum string) (*types.LBSVC, error)
	SVCDump() ([]types.LBSVC, error)
	RevNATAdd(id types.ServiceID, revNAT types.L3n4Addr) error
	RevNATDelete(id types.ServiceID) error
	RevNATDeleteAll() error
	RevNATGet(id types.ServiceID) (*types.L3n4Addr, error)
	RevNATDump() ([]types.L3n4AddrID, error)
}

// CiliumBackend is the interface for both client and daemon.
type CiliumBackend interface {
	bpfBackend
	control
	ipamBackend
	labelBackend
	policyBackend
	LBBackend
}

// CiliumDaemonBackend is the interface for daemon only.
type CiliumDaemonBackend interface {
	CiliumBackend
	ui
}
