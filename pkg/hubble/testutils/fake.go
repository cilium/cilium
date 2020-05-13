// Copyright 2019 Authors of Hubble
// Copyright 2020 Authors of Cilium
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

package testutils

import (
	"net"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ipcache"

	"github.com/golang/protobuf/ptypes/timestamp"
)

type FakeGetFlowsServer struct {
	OnSend func(response *observerpb.GetFlowsResponse) error
	*FakeGRPCServerStream
}

func (s *FakeGetFlowsServer) Send(response *observerpb.GetFlowsResponse) error {
	if s.OnSend != nil {
		// TODO: completely convert this into using flowpb.Flow
		return s.OnSend(response)
	}
	panic("OnSend not set")
}

// FakeFQDNCache is used for unit tests that needs FQDNCache and/or DNSGetter.
type FakeFQDNCache struct {
	OnInitializeFrom func(entries []*models.DNSLookup)
	OnAddDNSLookup   func(epID uint32, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32)
	OnGetNamesOf     func(epID uint32, ip net.IP) []string
}

// InitializeFrom implements FQDNCache.InitializeFrom.
func (f *FakeFQDNCache) InitializeFrom(entries []*models.DNSLookup) {
	if f.OnInitializeFrom != nil {
		f.OnInitializeFrom(entries)
		return
	}
	panic("InitializeFrom([]*models.DNSLookup) should not have been called since it was not defined")
}

// AddDNSLookup implements FQDNCache.AddDNSLookup.
func (f *FakeFQDNCache) AddDNSLookup(epID uint32, lookupTime time.Time, domainName string, ips []net.IP, ttl uint32) {
	if f.OnAddDNSLookup != nil {
		f.OnAddDNSLookup(epID, lookupTime, domainName, ips, ttl)
		return
	}
	panic("AddDNSLookup(uint32, time.Time, string, []net.IP, uint32) should not have been called since it was not defined")
}

// GetNamesOf implements FQDNCache.GetNameOf.
func (f *FakeFQDNCache) GetNamesOf(epID uint32, ip net.IP) []string {
	if f.OnGetNamesOf != nil {
		return f.OnGetNamesOf(epID, ip)
	}
	panic("GetNamesOf(uint32, net.IP) should not have been called since it was not defined")
}

// NoopDNSGetter always returns an empty response.
var NoopDNSGetter = FakeFQDNCache{
	OnGetNamesOf: func(sourceEpID uint32, ip net.IP) (fqdns []string) {
		return nil
	},
}

// FakeEndpointGetter is used for unit tests that needs EndpointGetter.
type FakeEndpointGetter struct {
	OnGetEndpointInfo func(ip net.IP) (endpoint v1.EndpointInfo, ok bool)
}

// GetEndpointInfo implements EndpointGetter.GetEndpointInfo.
func (f *FakeEndpointGetter) GetEndpointInfo(ip net.IP) (endpoint v1.EndpointInfo, ok bool) {
	if f.OnGetEndpointInfo != nil {
		return f.OnGetEndpointInfo(ip)
	}
	panic("OnGetEndpointInfo not set")
}

// NoopEndpointGetter always returns an empty response.
var NoopEndpointGetter = FakeEndpointGetter{
	OnGetEndpointInfo: func(ip net.IP) (endpoint v1.EndpointInfo, ok bool) {
		return nil, false
	},
}

// FakeIPGetter is used for unit tests that needs IPGetter.
type FakeIPGetter struct {
	OnGetIPIdentity func(ip net.IP) (id ipcache.IPIdentity, ok bool)
}

// GetIPIdentity implements FakeIPGetter.GetIPIdentity.
func (f *FakeIPGetter) GetIPIdentity(ip net.IP) (id ipcache.IPIdentity, ok bool) {
	if f.OnGetIPIdentity != nil {
		return f.OnGetIPIdentity(ip)
	}
	panic("OnGetIPIdentity not set")
}

// NoopIPGetter always returns an empty response.
var NoopIPGetter = FakeIPGetter{
	OnGetIPIdentity: func(ip net.IP) (id ipcache.IPIdentity, ok bool) {
		return ipcache.IPIdentity{}, false
	},
}

// FakeServiceGetter is used for unit tests that need ServiceGetter.
type FakeServiceGetter struct {
	OnGetServiceByAddr func(ip net.IP, port uint16) (service flowpb.Service, ok bool)
}

// GetServiceByAddr implements FakeServiceGetter.GetServiceByAddr.
func (f *FakeServiceGetter) GetServiceByAddr(ip net.IP, port uint16) (service flowpb.Service, ok bool) {
	if f.OnGetServiceByAddr != nil {
		return f.OnGetServiceByAddr(ip, port)
	}
	panic("OnGetServiceByAddr not set")
}

// NoopServiceGetter always returns an empty response.
var NoopServiceGetter = FakeServiceGetter{
	OnGetServiceByAddr: func(ip net.IP, port uint16) (service flowpb.Service, ok bool) {
		return flowpb.Service{}, false
	},
}

// FakeIdentityGetter is used for unit tests that need IdentityGetter.
type FakeIdentityGetter struct {
	OnGetIdentity func(securityIdentity uint32) (*models.Identity, error)
}

// GetIdentity implements IdentityGetter.GetIPIdentity.
func (f *FakeIdentityGetter) GetIdentity(securityIdentity uint32) (*models.Identity, error) {
	if f.OnGetIdentity != nil {
		return f.OnGetIdentity(securityIdentity)
	}
	panic("OnGetIdentity not set")
}

// NoopIdentityGetter always returns an empty response.
var NoopIdentityGetter = FakeIdentityGetter{
	OnGetIdentity: func(securityIdentity uint32) (*models.Identity, error) {
		return &models.Identity{}, nil
	},
}

// FakeEndpointsHandler implements EndpointsHandler interface for unit testing.
type FakeEndpointsHandler struct {
	FakeSyncEndpoints            func([]*v1.Endpoint)
	FakeUpdateEndpoint           func(*v1.Endpoint)
	FakeDeleteEndpoint           func(*v1.Endpoint)
	FakeFindEPs                  func(epID uint64, ns, pod string) []v1.Endpoint
	FakeGetEndpoint              func(ip net.IP) (endpoint *v1.Endpoint, ok bool)
	FakeGetEndpointByContainerID func(id string) (endpoint *v1.Endpoint, ok bool)
	FakeGetEndpointByPodName     func(namespace string, name string) (*v1.Endpoint, bool)
}

// SyncEndpoints calls FakeSyncEndpoints.
func (f *FakeEndpointsHandler) SyncEndpoints(eps []*v1.Endpoint) {
	if f.FakeSyncEndpoints != nil {
		f.FakeSyncEndpoints(eps)
		return
	}
	panic("SyncEndpoints([]*v1.Endpoint) should not have been called since it was not defined")
}

// UpdateEndpoint calls FakeUpdateEndpoint.
func (f *FakeEndpointsHandler) UpdateEndpoint(ep *v1.Endpoint) {
	if f.FakeUpdateEndpoint != nil {
		f.FakeUpdateEndpoint(ep)
		return
	}
	panic("UpdateEndpoint(*v1.Endpoint) should not have been called since it was not defined")
}

// DeleteEndpoint calls FakeDeleteEndpoint.
func (f *FakeEndpointsHandler) DeleteEndpoint(ep *v1.Endpoint) {
	if f.FakeDeleteEndpoint != nil {
		f.FakeDeleteEndpoint(ep)
		return
	}
	panic("DeleteEndpoint(*v1.Endpoint) should not have been called since it was not defined")
}

// FindEPs calls FakeFindEPs.
func (f *FakeEndpointsHandler) FindEPs(epID uint64, ns, pod string) []v1.Endpoint {
	if f.FakeFindEPs != nil {
		return f.FakeFindEPs(epID, ns, pod)
	}
	panic(" FindEPs(epID uint64, ns, pod string) should not have been called since it was not defined")
}

// GetEndpoint calls FakeGetEndpoint.
func (f *FakeEndpointsHandler) GetEndpoint(ip net.IP) (ep *v1.Endpoint, ok bool) {
	if f.FakeGetEndpoint != nil {
		return f.FakeGetEndpoint(ip)
	}
	panic("GetEndpoint(ip net.IP) (ep *v1.Endpoint, ok bool) should not have been called since it was not defined")
}

// GetEndpointByContainerID calls FakeGetEndpointByContainerID.
func (f *FakeEndpointsHandler) GetEndpointByContainerID(id string) (ep *v1.Endpoint, ok bool) {
	if f.FakeGetEndpointByContainerID != nil {
		return f.FakeGetEndpointByContainerID(id)
	}
	panic("GetEndpointByContainerID(id string) (ep *v1.Endpoint, ok bool) should not have been called since it was not defined")
}

// GetEndpointByPodName calls FakeGetEndpointByPodName.
func (f *FakeEndpointsHandler) GetEndpointByPodName(namespace string, name string) (ep *v1.Endpoint, ok bool) {
	if f.FakeGetEndpointByPodName != nil {
		return f.FakeGetEndpointByPodName(namespace, name)
	}
	panic("GetEndpointByPodName(namespace string, name string) (ep *v1.Endpoint, ok bool) should not have been called since it was not defined")
}

// FakeCiliumClient implements CliliumClient interface for unit testing.
type FakeCiliumClient struct {
	FakeEndpointList    func() ([]*models.Endpoint, error)
	FakeGetEndpoint     func(uint64) (*models.Endpoint, error)
	FakeGetIdentity     func(uint64) (*models.Identity, error)
	FakeGetFqdnCache    func() ([]*models.DNSLookup, error)
	FakeGetIPCache      func() ([]*models.IPListEntry, error)
	FakeGetServiceCache func() ([]*models.Service, error)
}

// EndpointList calls FakeEndpointList.
func (c *FakeCiliumClient) EndpointList() ([]*models.Endpoint, error) {
	if c.FakeEndpointList != nil {
		return c.FakeEndpointList()
	}
	panic("EndpointList() should not have been called since it was not defined")
}

// GetEndpoint calls FakeGetEndpoint.
func (c *FakeCiliumClient) GetEndpoint(id uint64) (*models.Endpoint, error) {
	if c.FakeGetEndpoint != nil {
		return c.FakeGetEndpoint(id)
	}
	panic("GetEndpoint(uint64) should not have been called since it was not defined")
}

// GetIdentity calls FakeGetIdentity.
func (c *FakeCiliumClient) GetIdentity(id uint64) (*models.Identity, error) {
	if c.FakeGetIdentity != nil {
		return c.FakeGetIdentity(id)
	}
	panic("GetIdentity(uint64) should not have been called since it was not defined")
}

// GetFqdnCache calls FakeGetFqdnCache.
func (c *FakeCiliumClient) GetFqdnCache() ([]*models.DNSLookup, error) {
	if c.FakeGetFqdnCache != nil {
		return c.FakeGetFqdnCache()
	}
	panic("GetFqdnCache() should not have been called since it was not defined")
}

// GetIPCache calls FakeGetIPCache.
func (c *FakeCiliumClient) GetIPCache() ([]*models.IPListEntry, error) {
	if c.FakeGetIPCache != nil {
		return c.FakeGetIPCache()
	}
	panic("GetIPCache() should not have been called since it was not defined")
}

// GetServiceCache calls FakeGetServiceCache.
func (c *FakeCiliumClient) GetServiceCache() ([]*models.Service, error) {
	if c.FakeGetServiceCache != nil {
		return c.FakeGetServiceCache()
	}
	panic("GetServiceCache() should not have been called since it was not defined")
}

// FakeFlow implements v1.Flow for unit tests. All interface methods
// return values exposed in the fields.
type FakeFlow struct {
	Time               *timestamp.Timestamp
	Verdict            flowpb.Verdict
	DropReason         uint32
	Ethernet           *flowpb.Ethernet
	IP                 *flowpb.IP
	L4                 *flowpb.Layer4
	Source             *flowpb.Endpoint
	Destination        *flowpb.Endpoint
	Type               flowpb.FlowType
	NodeName           string
	SourceNames        []string
	DestinationNames   []string
	L7                 *flowpb.Layer7
	Reply              bool
	EventType          *flowpb.CiliumEventType
	SourceService      *flowpb.Service
	DestinationService *flowpb.Service
	TrafficDirection   flowpb.TrafficDirection
	PolicyMatchType    uint32
}

// Reset implements flowpb.Message for the FakeFlow.
func (f *FakeFlow) Reset() {}

// ProtoMessage implements flowpb.Message for the FakeFlow.
func (f *FakeFlow) ProtoMessage() {}

// String implements flowpb.Message for the FakeFlow.
func (f *FakeFlow) String() string { return "fake flow message" }

// GetTime implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetTime() *timestamp.Timestamp {
	return f.Time
}

// GetVerdict implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetVerdict() flowpb.Verdict {
	return f.Verdict
}

// GetDropReason implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetDropReason() uint32 {
	return f.DropReason
}

// GetEthernet implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetEthernet() *flowpb.Ethernet {
	return f.Ethernet
}

// GetIP implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetIP() *flowpb.IP {
	return f.IP
}

// GetL4 implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetL4() *flowpb.Layer4 {
	return f.L4
}

// GetSource implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetSource() *flowpb.Endpoint {
	return f.Source
}

// GetDestination implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetDestination() *flowpb.Endpoint {
	return f.Destination
}

// GetType implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetType() flowpb.FlowType {
	return f.Type
}

// GetNodeName implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetNodeName() string {
	return f.NodeName
}

// GetSourceNames implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetSourceNames() []string {
	return f.SourceNames
}

// GetDestinationNames implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetDestinationNames() []string {
	return f.DestinationNames
}

// GetL7 implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetL7() *flowpb.Layer7 {
	return f.L7
}

// GetReply implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetReply() bool {
	return f.Reply
}

// GetEventType implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetEventType() *flowpb.CiliumEventType {
	return f.EventType
}

// GetSourceService implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetSourceService() *flowpb.Service {
	return f.SourceService
}

// GetDestinationService implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetDestinationService() *flowpb.Service {
	return f.DestinationService
}

// GetTrafficDirection implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetTrafficDirection() flowpb.TrafficDirection {
	return f.TrafficDirection
}

// GetPolicyMatchType implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetPolicyMatchType() uint32 {
	return f.PolicyMatchType
}

// GetSummary implements v1.Flow for the FakeFlow.
func (f *FakeFlow) GetSummary() string {
	return "deprecated"
}
