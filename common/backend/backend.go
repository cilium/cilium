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
	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

type bpfBackend interface {
	EndpointJoin(ep endpoint.Endpoint) error
	EndpointLeave(epID uint16) error
	EndpointLeaveByDockerEPID(dockerEPID string) error
	EndpointGet(epID uint16) (*endpoint.Endpoint, error)
	EndpointGetByDockerEPID(dockerEPID string) (*endpoint.Endpoint, error)
	EndpointGetByDockerID(dockerID string) (*endpoint.Endpoint, error)
	EndpointsGet() ([]endpoint.Endpoint, error)
	EndpointUpdate(epID uint16, opts option.OptionMap) error
	EndpointSave(ep endpoint.Endpoint) error
	EndpointLabelsGet(epID uint16) (*labels.OpLabels, error)
	EndpointLabelsUpdate(epID uint16, labelOp labels.LabelOp) error
}

type ipamBackend interface {
	GetIPAMConf(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error)
	AllocateIP(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMRep, error)
	ReleaseIP(ipamType ipam.IPAMType, options ipam.IPAMReq) error
}

type labelBackend interface {
	PutLabels(labels labels.Labels, contĨD string) (*policy.Identity, bool, error)
	GetLabels(uuid policy.NumericIdentity) (*policy.Identity, error)
	GetLabelsBySHA256(sha256sum string) (*policy.Identity, error)
	DeleteLabelsByUUID(uuid policy.NumericIdentity, contĨD string) error
	DeleteLabelsBySHA256(sha256sum, contID string) error
	GetMaxLabelID() (policy.NumericIdentity, error)
}

type policyBackend interface {
	PolicyAdd(path string, node *policy.Node) error
	PolicyDelete(path, coverSHA256 string) error
	PolicyGet(path string) (*policy.Node, error)
	PolicyCanConsume(ctx *policy.SearchContext) (*policy.SearchContextReply, error)
}

type control interface {
	Ping() (*types.PingResponse, error)
	Update(opts option.OptionMap) error
	SyncState(path string, clean bool) error
	GlobalStatus() (*endpoint.StatusResponse, error)
}

type LBBackend interface {
	SVCAdd(fe types.L3n4AddrID, be []types.LBBackendServer, addRevNAT bool) error
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
	WRRDump() ([]lbmap.ServiceRR, error)
	SyncLBMap() error
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
}
